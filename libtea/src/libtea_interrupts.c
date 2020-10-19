
/* See LICENSE file for license and copyright information */

/* Start libtea_interrupts.c */
//---------------------------------------------------------------------------

#include "libtea_interrupts.h"

/* See irq_entry.S to see how these are used. */

void libtea_irq_gate_func(void);
libtea_irq_callback libtea_irq_callback_table[256] = {0};
libtea_privileged_callback libtea_irq_gate_callback = NULL;
uint8_t libtea_vector_hack = 0;


void libtea__assert_pinned_to_core() {
  /* For changing GDT and IDT etc we *must* be pinned to a core, so cancel init otherwise */
  cpu_set_t set;
  CPU_ZERO(&set);
  sched_getaffinity(0, sizeof(cpu_set_t), &set);
  if(CPU_COUNT(&set) > 1){
    libtea_info("Cannot initalize interrupt functionality, your process must be pinned to a single core. You can do this using libtea_pin_to_core().");
    exit(EXIT_FAILURE);
  }
}


void libtea__interrupts_init(){
  /* Ensure IRQ handler asm code is not subject to demand-paging */
  libtea_info("Locking IRQ handler pages %p/%p", &libtea_ss_irq_handler, &libtea_ss_irq_fired);
  libtea_assert( !mlock(&libtea_ss_irq_handler, 4096) );
  libtea_assert( !mlock((void*) &libtea_ss_irq_fired, 4096) );
}


/* used by irq_entry.S */
void libtea_irq_handler_c(uint8_t *rsp, uint8_t vector) {
  if (libtea_irq_callback_table[vector]){
    libtea_irq_callback_table[vector](rsp);
  }

  /* Inline libtea_apic_write below without instance variable to preserve var placement for ASM */
  volatile uint32_t *addr = (volatile uint32_t *)(libtea_apic_base + LIBTEA_APIC_EOI);
  asm volatile ("movl %1, %0\n\t" : "=m"(*addr) :"r"(0x0) : );
}

void libtea_map_gdt(libtea_instance* instance, libtea_gdt* gdt) {
  libtea__assert_pinned_to_core();

  libtea_descriptor_table_register gdtr = {0};
  asm volatile ("sgdt %0" :"=m"(gdtr) :: );
  int entries = ((gdtr.size)+1)/sizeof(libtea_seg_descriptor);
  print_descriptor_table_register(&gdtr, entries);
  libtea_assert(gdtr.address);

  void* gdt_vaddr = libtea_remap_address(instance, gdtr.address, LIBTEA_PAGE, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, true);
  libtea_info("Established user space GDT mapping at %p", gdt_vaddr);
  libtea_assert(gdt_vaddr);

  gdt->base = (libtea_seg_descriptor*) gdt_vaddr;
  gdt->entries = entries;
}


void libtea_map_idt(libtea_instance* instance, libtea_idt* idt) {
  libtea__assert_pinned_to_core();

  libtea_descriptor_table_register idtr = {0};
  asm volatile ("sidt %0" :"=m"(idtr) :: );
  int entries = (idtr.size+1)/sizeof(libtea_gate_descriptor);
  print_descriptor_table_register(&idtr, entries);
  libtea_assert(idtr.address);
 
  void* idt_vaddr = libtea_remap_address(instance, idtr.address, LIBTEA_PAGE, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, true);
  libtea_info("Established user space IDT mapping at %p", idt_vaddr);
  libtea_assert(idt_vaddr);

  idt->base = (libtea_gate_descriptor*) idt_vaddr;
  idt->entries = entries;
}


void libtea_print_gdt(libtea_gdt* gdt) {
  int i;
  libtea_always_print_info("--------------------------------------------------------------------------------");
  for (i =0; i < gdt->entries; i++) {
    libtea_print_seg_descriptor(libtea_seg_ptr(gdt->base, i), i);
  }
  libtea_always_print_info("--------------------------------------------------------------------------------");
}


void libtea_print_idt(libtea_idt* idt) {
  int i;
  libtea_always_print_info("--------------------------------------------------------------------------------");
  for (i =0; i < idt->entries; i++) {
    libtea_print_gate_descriptor(libtea_gate_ptr(idt->base, i), i);
  }
  libtea_always_print_info("--------------------------------------------------------------------------------");
}


void libtea_print_gate_descriptor(libtea_gate_descriptor* gate, int idx) {
  libtea_always_print_info("IDT[%3d] @%p = %p (seg sel 0x%x); p=%d; dpl=%d; type=%02d; ist=%d",
    idx, gate, (void*) libtea_gate_offset(gate), gate->segment, gate->p, gate->dpl, gate->type, gate->ist);
}


void libtea_print_seg_descriptor(libtea_seg_descriptor* desc, int idx) {
  libtea_always_print_info("GDT[%3d] @%p=0x%08x / 0x%05x (seg sel 0x%02x); p=%d; dpl=%d; type=%2d; g=%d",
    idx, desc, (unsigned int) libtea_seg_base(desc), (int) libtea_seg_limit(desc),
    idx*8+desc->dpl, desc->p, desc->dpl, desc->type, desc->g);
}


libtea_gate_descriptor* libtea_get_gate_descriptor(libtea_gdt* gdt, int idx) {
  /* System descriptors are expanded to 16 bytes (occupying the space of two entries). */
  if(!(idx >= 0 && idx < (gdt->entries-1))) return NULL;
  return (libtea_gate_descriptor*) (libtea_seg_ptr(gdt->base, idx));
}


libtea_seg_descriptor* libtea_get_seg_descriptor(libtea_gdt* gdt, int idx) {
  if(! (idx >= 0 && idx < gdt->entries)) return NULL;
  return libtea_seg_ptr(gdt->base, idx);
}


int libtea_get_cpl() {
  int rv;
  asm("mov %%cs, %0\n\t"
      "and $0x3, %0\n\t"
      :"=r"(rv)::);
  return rv;
}


/* NOTE: make sure SMAP/SMEP are disabled when installing ring 0 user space call gates */
void libtea_install_call_gate(libtea_gdt* gdt, int gdt_idx, libtea_cs cs, libtea_call_gate_callback handler) {
  libtea__assert_pinned_to_core();
  libtea_assert(gdt_idx >= 0 && gdt_idx < (gdt->entries-1));
  libtea_assert(!libtea_get_seg_descriptor(gdt, gdt_idx)->p && !libtea_get_seg_descriptor(gdt, gdt_idx+1)->p);

  libtea_gate_descriptor* g = libtea_get_gate_descriptor(gdt, gdt_idx);
  g->offset_low    = LIBTEA_PTR_LOW(handler);
  g->offset_middle = LIBTEA_PTR_MIDDLE(handler);
  g->offset_high   = LIBTEA_PTR_HIGH(handler);
  g->p             = 1;
  g->segment       = cs;
  g->dpl           = LIBTEA_USER_DPL;
  g->type          = LIBTEA_GATE_CALL;
  g->ist           = 0;
}


void libtea_do_far_call(int gdt_idx) {
  libtea_call_gate_pt p = {
    .segment = (gdt_idx*8+LIBTEA_USER_DPL)
  };
  asm("lcall *%0\n\t"::"m"(p):);
}


void libtea_install_irq_handler(libtea_idt *idt, void* asm_handler, int vector, libtea_cs seg, libtea_gate_type type){
  libtea__assert_pinned_to_core();
  libtea_assert(vector >= 0 && vector < idt->entries);

  libtea_gate_descriptor *gate = libtea_gate_ptr(idt->base, vector);
  gate->offset_low    = LIBTEA_PTR_LOW(asm_handler);
  gate->offset_middle = LIBTEA_PTR_MIDDLE(asm_handler);
  gate->offset_high   = LIBTEA_PTR_HIGH(asm_handler);

  gate->p = 1;
  gate->segment = seg;
  gate->dpl = LIBTEA_USER_DPL;
  gate->type = type;
  gate->ist = 0;

  libtea_info("Installed asm IRQ handler at %x:%p", seg, asm_handler);
  libtea_print_gate_descriptor(gate, vector);
}


void libtea_install_user_irq_handler(libtea_idt *idt, void* asm_handler, int vector) {
  /*
   * Note we explicitly use a trap gate here and not an interrupt gate,
   * since the Interrupt Enable (IE) flag won't get reset on iretq in user
   * space, resulting in a stalled CPU.
   */
  return libtea_install_irq_handler(idt, asm_handler, vector, LIBTEA_USER_CS, LIBTEA_GATE_TRAP);
}


void libtea_install_kernel_irq_handler(libtea_idt *idt, void *asm_handler, int vector){
  /* We can use an interrupt gate to make the ring 0 handler uninterruptible. */
  return libtea_install_irq_handler(idt, asm_handler, vector, LIBTEA_KERNEL_CS, LIBTEA_GATE_INTERRUPT);
}


void libtea_exec_in_kernel(libtea_instance* instance, libtea_privileged_callback callback, int cpu) {
  libtea__assert_pinned_to_core();

  libtea_idt idt;
  if (!libtea_irq_gate_callback) {
    libtea_map_idt(instance, &idt);
    /* We use a trap gate to make the code interruptible. */
    libtea_install_irq_handler(&idt, libtea_irq_gate_func, LIBTEA_IRQ_VECTOR+4, LIBTEA_KERNEL_CS, LIBTEA_GATE_TRAP);
    libtea_unmap_address_range((size_t)idt.base, 4096);
  }

  libtea_irq_gate_callback = callback;
  asm("int %0\n\t" ::"i"(LIBTEA_IRQ_VECTOR+4):);
}


void libtea_apic_init(libtea_instance* instance) {
  libtea__assert_pinned_to_core();
  if (libtea_apic_base) return;

  uintptr_t apic_base_addr = 0x0;
  uint64_t apic_base_msr = 0x0;
  apic_base_msr = libtea_read_system_reg(instance, sched_getcpu(), LIBTEA_IA32_APIC_BASE_MSR);
  libtea_assert( (apic_base_msr & LIBTEA_APIC_BASE_MSR_ENABLE) );
  libtea_assert( !(apic_base_msr & LIBTEA_APIC_BASE_MSR_X2APIC) );
  apic_base_addr = apic_base_msr & ~LIBTEA_APIC_BASE_ADDR_MASK;

  libtea_apic_base = libtea_map_physical_address_range(instance, apic_base_addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, true);
  libtea_info("Established local memory mapping for APIC_BASE=%p at %p", (void*) apic_base_addr, libtea_apic_base);
  libtea_info("APIC_ID=%x; LVTT=%x; TDCR=%x", libtea_apic_read(instance, LIBTEA_APIC_ID), libtea_apic_read(instance, LIBTEA_APIC_LVTT), libtea_apic_read(instance, LIBTEA_APIC_TDCR));
  libtea_assert(libtea_apic_read(instance, LIBTEA_APIC_ID) != -1);
}


void libtea_apic_timer_oneshot(libtea_instance* instance, uint8_t vector) {
  libtea_apic_init(instance);

  /* Save APIC timer config to restore later */
  libtea_apic_lvtt = libtea_apic_read(instance, LIBTEA_APIC_LVTT);
  libtea_apic_tdcr = libtea_apic_read(instance, LIBTEA_APIC_TDCR);

  libtea_apic_write(instance, LIBTEA_APIC_LVTT, vector | LIBTEA_APIC_LVTT_ONESHOT);
  libtea_apic_write(instance, LIBTEA_APIC_TDCR, LIBTEA_APIC_TDR_DIV_2);
  // NOTE: APIC seems not to handle divide by 1 properly (?)
  // see also: http://wiki.osdev.org/APIC_timer)
  libtea_info("APIC timer one-shot mode with division 2 (lvtt=%x/tdcr=%x)", libtea_apic_read(instance, LIBTEA_APIC_LVTT), libtea_apic_read(instance, LIBTEA_APIC_TDCR));
}


void libtea_apic_timer_deadline(libtea_instance* instance) {
  libtea_apic_init(instance);

  if (libtea_apic_lvtt) {
    libtea_apic_write(instance, LIBTEA_APIC_LVTT, libtea_apic_lvtt);
    libtea_apic_write(instance, LIBTEA_APIC_TDCR, libtea_apic_tdcr);
    libtea_info("Restored APIC_LVTT=%x/TDCR=%x", libtea_apic_read(instance, LIBTEA_APIC_LVTT), libtea_apic_read(instance, LIBTEA_APIC_TDCR));
    libtea_apic_lvtt = libtea_apic_tdcr = 0x0;
  }

  /* Writing a non-zero value to the TSC_DEADLINE MSR will arm the timer */
  libtea_write_system_reg(instance, sched_getcpu(), LIBTEA_IA32_TSC_DEADLINE_MSR, 1);
  libtea_apic_lvtt = libtea_apic_tdcr = 0x0;
}


void libtea_apic_set_timer(libtea_instance* instance, int time){
  libtea_apic_write(instance, LIBTEA_APIC_TMICT, time);
}


void libtea_apic_set_timer_unsafe(int time){
  libtea_apic_write_unsafe(LIBTEA_APIC_TMICT, time);
}


void libtea_send_ipi_to_self(libtea_instance* instance, int n){
  libtea_apic_write(instance, LIBTEA_APIC_ICR, LIBTEA_APIC_ICR_VECTOR(n) | LIBTEA_APIC_ICR_DELIVERY_FIXED | LIBTEA_APIC_ICR_LEVEL_ASSERT | LIBTEA_APIC_ICR_DEST_SELF);
}


/* End libtea_interrupts.c */
//---------------------------------------------------------------------------
