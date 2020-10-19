
/* See LICENSE file for license and copyright information */

/* Note: Libtea's interrupt functionality is currently not compatible with Windows, only Linux is supported */

#ifndef LIBTEA_INTERRUPTS_H
#define LIBTEA_INTERRUPTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libtea_common.h"
#include <fcntl.h>
#include <sys/ioctl.h>

//From Linux kernel arch/x86/include/asm/segment.h,
//arch/x86/include/asm/desc_defs.h
#define LIBTEA_KERNEL_DPL                0
#define LIBTEA_USER_DPL                  3
#define LIBTEA_GDT_ENTRY_USER_CS         6
#define LIBTEA_GDT_ENTRY_KERNEL_CS       2

#define LIBTEA_APIC_BASE_MSR_X2APIC      0x400
#define LIBTEA_APIC_BASE_MSR_ENABLE      0x800
#define LIBTEA_APIC_BASE_ADDR_MASK       0xfff
#define LIBTEA_APIC_ICR                  0x300
#define LIBTEA_APIC_LVTT                 0x320
#define LIBTEA_APIC_TDCR                 0x3e0
#define LIBTEA_APIC_TMICT                0x380
#define LIBTEA_APIC_TMCCT                0x390
#define LIBTEA_APIC_ID                   0x20
#define LIBTEA_APIC_EOI                  0xb0
#define LIBTEA_APIC_TPR	                 0x80
#define LIBTEA_APIC_PPR	                 0xa0
#define LIBTEA_APIC_TDR_DIV_1            0xb
#define LIBTEA_APIC_TDR_DIV_2            0x0
#define LIBTEA_APIC_LVTT_ONESHOT         (0 << 17)
#define LIBTEA_APIC_LVTT_DEADLINE        (2 << 17)
#define LIBTEA_APIC_IPI_CFG              0xc08f1
#define LIBTEA_APIC_ICR_VECTOR(n)        (n & 0xFF)
#define LIBTEA_APIC_ICR_DELIVERY_FIXED   (0x0 << 8)
#define LIBTEA_APIC_ICR_LEVEL_ASSERT     (0x1 << 14)
#define LIBTEA_APIC_ICR_DEST_SELF        (0x1 << 18)

#define LIBTEA_IA32_APIC_BASE_MSR         0x1b
#define LIBTEA_IA32_TSC_DEADLINE_MSR      0x6e0

#define LIBTEA_PTR_LOW(x) ((unsigned long long)(x) & 0xFFFF)
#define LIBTEA_PTR_MIDDLE(x) (((unsigned long long)(x) >> 16) & 0xFFFF)
#define LIBTEA_PTR_HIGH(x) ((unsigned long long)(x) >> 32)
#define libtea_gate_offset(g) ((g)->offset_low | ((unsigned long)(g)->offset_middle << 16) | ((unsigned long)(g)->offset_high << 32))
#define libtea_gate_ptr(base, idx) ((libtea_gate_descriptor*) (((void*) base) + idx*sizeof(libtea_gate_descriptor)))
#define libtea_seg_base(d) ((d)->base0 | ((unsigned long)(d)->base1 << 16) | ((unsigned long)(d)->base2 << 24))
#define libtea_seg_limit(d) ((d)->limit0 | ((unsigned long)(d)->limit1 << 16))
#define libtea_seg_ptr(gdt_base, idx) ((libtea_seg_descriptor*) (((void*) gdt_base) + idx*sizeof(libtea_seg_descriptor)))

typedef void (*libtea_call_gate_callback)(void);
typedef void (*libtea_irq_callback)(uint8_t *rsp);
typedef void (*libtea_privileged_callback)(void);

extern void libtea_ss_irq_handler(void);
extern int volatile libtea_ss_irq_fired, libtea_ss_irq_count, libtea_ss_irq_cpl;


/**
 * Structure for a 16-byte x86 call gate
 * (from Linux kernel arch/x86/include/asm/desc_defs.h)
 */
typedef struct {
  uint16_t offset_low;
  uint16_t segment;
  unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
  uint16_t offset_middle;
  uint32_t offset_high; //reserved, 64-bit only
  uint32_t zero1; //reserved, 64-bit only
} __attribute__((packed)) libtea_gate_descriptor;

/**
 * Available call gate types
 */
typedef enum {
  LIBTEA_GATE_INTERRUPT = 0xE,
  LIBTEA_GATE_TRAP = 0xF,
  LIBTEA_GATE_CALL = 0xC,
  LIBTEA_GATE_TASK = 0x5,
} libtea_gate_type;

typedef struct {
  uint32_t offset;
  uint16_t segment;
} __attribute__((packed)) libtea_call_gate_pt;

/**
 * Code Segment (CS) values used by Linux for user-mode and kernel-mode
 */
typedef enum {
  LIBTEA_KERNEL_CS = LIBTEA_GDT_ENTRY_KERNEL_CS*8+LIBTEA_KERNEL_DPL,
  LIBTEA_USER_CS   = LIBTEA_GDT_ENTRY_USER_CS*8+LIBTEA_USER_DPL,
} libtea_cs;

//desc_ptr in Linux source - see arch/x86/include/asm/desc_defs.h
typedef struct {
  uint16_t size;  //Size of GDT/IDT - 1
  uint64_t address; //Virtual address
  //uint32_t unused; //the unused upper 32 bits of the 64-bit val
} __attribute__((packed)) libtea_descriptor_table_register;

/**
 * Structure for an 8-byte segment descriptor (x86).
 * Note: LDT/TSS GDT descriptors are structured differently
 * (see Linux kernel arch/x86/include/asm/desc_defs.h)
 */
typedef struct {
  uint16_t limit0;
  uint16_t base0;
  unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
  unsigned limit1: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
} __attribute__((packed)) libtea_seg_descriptor;

/**
 * Structure for an x86 Global Descriptor Table (GDT)
 */
typedef struct {
  libtea_seg_descriptor* base;
  size_t   entries;
} libtea_gdt;

/**
 * Structure for an x86 Interrupt Descriptor Table (IDT)
 */
typedef struct {
  libtea_gate_descriptor* base;
  size_t     entries;
} libtea_idt;

#define print_descriptor_table_register(dtr, entries)                          \
    libtea_info("Address=%p/size=%d (%d entries)", \
        (void*) (dtr)->address, (dtr)->size, entries)

#define libtea_apic_timer_irq(instance, tsc) libtea_apic_write(instance, LIBTEA_APIC_TMICT, tsc)
#define libtea_apic_send_ipi_self(instance, n) libtea_apic_write(instance, LIBTEA_APIC_ICR, LIBTEA_APIC_ICR_VECTOR(n) | LIBTEA_APIC_ICR_DELIVERY_FIXED | LIBTEA_APIC_ICR_LEVEL_ASSERT | LIBTEA_APIC_ICR_DEST_SELF)

extern void* libtea_apic_base;
void* libtea_dummy_pt = NULL;
uint32_t libtea_apic_lvtt = 0x0, libtea_apic_tdcr = 0x0;

void libtea__interrupts_init();

/**
 * Establishes a user-space mapping for the Global Descriptor Table (GDT).
 *
 * :param instance: The libtea instance
 * :param gdt: Empty GDT which will be filled with the user-space mapped base and current GDT entries
 */
void libtea_map_gdt(libtea_instance* instance, libtea_gdt* gdt);


/**
 * Establishes a user-space mapping for the Interrupt Descriptor Table (IDT).
 *
 * :param instance: The libtea instance
 * :param idt: Empty IDT which will be filled with the user-space mapped base and current IDT entries
 */
void libtea_map_idt(libtea_instance* instance, libtea_idt* idt);


/**
 * Prints a Global Descriptor Table (GDT).
 *
 * :param gdt: The GDT to print
 */
void libtea_print_gdt(libtea_gdt* gdt);


/**
 * Prints an Interupt Descriptor Table (IDT).
 *
 * :param idt: The IDT to print
 */
void libtea_print_idt(libtea_idt* idt);


/**
 * Prints a call gate descriptor.
 *
 * :param gate: The gate descriptor to print
 * :param idx: The index of the descriptor
 */
void libtea_print_gate_descriptor(libtea_gate_descriptor* gate, int idx);


/**
 * Prints a segment descriptor.
 *
 * :param desc: The segment descriptor to print
 * :param idx: The index of the descriptor
 */
void libtea_print_seg_descriptor(libtea_seg_descriptor* desc, int idx);


/**
 * Returns the specified gate descriptor from the GDT.
 *
 * :param gdt: The GDT
 * :param idx: The descriptor index
 *
 * :return: The gate descriptor
 */
libtea_gate_descriptor* libtea_get_gate_descriptor(libtea_gdt* gdt, int idx);


/**
 * Returns the specified segment descriptor from the GDT.
 *
 * :param gdt: The GDT
 * :param idx: The descriptor index
 *
 * :return: The segment descriptor
 */
libtea_seg_descriptor* libtea_get_seg_descriptor(libtea_gdt* gdt, int idx);


/**
 * Returns the Current Privilege Level (CPL, or ring).
 *
 * :return: The CPL (0-3)
 */
int libtea_get_cpl(void);


/**
 * Installs a user-space custom call gate.
 * Note: ensure SMAP/SMEP are disabled before using this function.
 *
 * :param gdt: The GDT
 * :param gdt_idx: The index to install the call gate at
 * :param cs: Code segment for the call gate
 * :param handler: The call gate function to register
 */
void libtea_install_call_gate(libtea_gdt* gdt, int gdt_idx, libtea_cs cs, libtea_call_gate_callback handler);


/**
 * Does a far call to the call gate indicated.
 *
 * :param gdt_idx: Index of the call gate in the GDT
 */
void libtea_do_far_call(int gdt_idx);


/**
 * Installs a user-space ASM interrupt handler.
 * Warning: may cause occasional system crashes due to a race condition with the kernel,
 * prefer kernel-space handlers.
 *
 * :param idt: The IDT
 * :param asm_handler: The ASM handler to register
 * :param vector: The IRQ vector
 */
void libtea_install_user_irq_handler(libtea_idt *idt, void* asm_handler, int vector);


/**
 * Installs a kernel-space ASM interrupt handler.
 *
 * :param idt: The IDT
 * :param asm_handler: The ASM handler to register
 * :param vector: The IRQ vector
 */
void libtea_install_kernel_irq_handler(libtea_idt *idt, void *asm_handler, int vector);


/**
 * Installs and calls a ring 0 IRQ gate.
 *
 * :param instance: The libtea instance
 * :param callback: A callback containing privileged code to execute in ring 0
 * :param cpu: The CPU core to install the gate on
 */
void libtea_exec_in_kernel(libtea_instance* instance, libtea_privileged_callback callback, int cpu);


/**
 * Maps APIC timer MMIO registers into user space.
 * Must be run before other APIC functions can be used.
 *
 * NOTE: we require xAPIC mode, since "In x2APIC mode, the memory mapped
 * interface is not available and any access to the MMIO interface will behave
 * similar to that of a legacy xAPIC in globally disabled state" (Intel SDM
 * 10.12.2).
 *
 * Advised Linux command line parameters are: "nox2apic iomem=relaxed no_timer_check"
 *
 * :param instance: The libtea instance
 */
void libtea_apic_init(libtea_instance* instance);


/**
 * Sets up the APIC timer in one-shot mode.
 *
 * :param instance: The libtea instance
 * :param vector: Timer interrupt vector
 */
void libtea_apic_timer_oneshot(libtea_instance* instance, uint8_t vector);


/**
 * Sets up the APIC timer in deadline mode.
 *
 * :param instance: The libtea instance
 */
void libtea_apic_timer_deadline(libtea_instance* instance);


/**
 * Writes to a local APIC register.
 *
 * :param instance: The libtea instance
 * :param reg: The local APIC register to write
 * :param v: The value to write
 */
static inline void libtea_apic_write(libtea_instance* instance, uint32_t reg, uint32_t value){
 /*
  * From Linux kernel source: /arch/x86/include/asm/apic.h
  * NOTE: Intel SDM: "any access that touches bytes 4 through 15 of an APIC
  * register may cause undefined behavior and must not be executed."
  */
  volatile uint32_t *addr;
  if (!libtea_apic_base) libtea_apic_init(instance);

  addr = (volatile uint32_t *)(libtea_apic_base + reg);
  asm volatile ("movl %1, %0\n\t" :"=m"(*addr):"r"(value):);
}


/**
 * Writes to a local APIC register.
 * This version does not use the libtea instance and so is suitable for use in 
 * privileged callbacks. It is unsafe as it does not check that libtea APIC
 * functionality is initialized; this is your responsibility.
 *
 * :param instance: The libtea instance
 * :param reg: The local APIC register to write
 * :param v: The value to write
 */
static inline void libtea_apic_write_unsafe(uint32_t reg, uint32_t value){
  volatile uint32_t *addr;
  addr = (volatile uint32_t *)(libtea_apic_base + reg);
  asm volatile ("movl %1, %0\n\t" :"=m"(*addr):"r"(value):);
}


/**
 * Reads from a local APIC register.
 *
 * :param instance: The libtea instance
 * :param reg: The local APIC register to read
 *
 * :return: Register value
 */
static inline uint32_t libtea_apic_read(libtea_instance* instance, uint32_t reg){
  if (!libtea_apic_base) libtea_apic_init(instance);
  return *((volatile uint32_t *)(libtea_apic_base + reg));
}

/**
 * Reads from a local APIC register.
 * This version does not use the libtea instance and so is suitable for use in 
 * privileged callbacks. It is unsafe as it does not check that libtea APIC
 * functionality is initialized; this is your responsibility.
 * 
 * :param instance: The libtea instance
 * :param reg: The local APIC register to read
 *
 * :return: Register value
 */
static inline uint32_t libtea_apic_read_unsafe(uint32_t reg){
  return *((volatile uint32_t *)(libtea_apic_base + reg));
}


/**
 * Use to set the interval of the APIC timer.
 * 
 * :param instance: The libtea instance
 * :param time: The value to set
 */
void libtea_apic_set_timer(libtea_instance* instance, int time);


/**
 * Use to set the interval of the APIC timer.
 * This version does not use the libtea instance and so is suitable for use in 
 * privileged callbacks. It is unsafe as it does not check that libtea APIC
 * functionality is initialized; this is your responsibility.
 * 
 * :param time: The value to set
 */
void libtea_apic_set_timer_unsafe(int time);


/**
 * Sends an inter-processor interrupt (IPI) to the specified core.
 * 
 * :param instance: The libtea instance
 * :param n: The core to send the interrupt to
 */
void libtea_send_ipi_to_self(libtea_instance* instance, int n);


#ifdef __cplusplus
}
#endif

#endif //LIBTEA_INTERRUPTS_H
