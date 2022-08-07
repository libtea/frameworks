
/* See LICENSE file for license and copyright information */

#ifdef __cplusplus
extern "C" {
#endif

#include "../libtea.h"
#include <inttypes.h>

#define ISOLATED_CPU_CORE 1

void nop() {
  //This exists to check that we can run SOMETHING in kernel mode and return without a hang or error before we try to do anything more interesting.
  asm("nop");
}

void generate_software_interrupt() {
  asm("int %0" ::"i"(LIBTEA_IRQ_VECTOR):);
}

void generate_apic_timer_interrupt() {
    libtea_apic_set_timer_unsafe(10);
    int safeguard = 0;
    while(!libtea_ss_irq_fired && safeguard < 30000000) {
      //To avoid an endless loop (particularly problematic if executing in the kernel!) if for some reason the timer interrupt fails to fire
      safeguard++;
    }
}

int main(int argc, char **argv){

  libtea_instance* instance = libtea_init();
  if(!instance){
    libtea_info("Libtea test init failed.");
    return 1;
  }
  libtea_pin_to_core(getpid(), ISOLATED_CPU_CORE);

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 1: mapping GDT.");

  libtea_gdt gdt = {0};
  libtea_map_gdt(instance, &gdt);
  if(gdt.base != MAP_FAILED){
    libtea_print_gdt(&gdt);
    libtea_unmap_address_range((size_t)gdt.base, 4096);
    if(gdt.entries != 16){
      libtea_info("Test 1 failed: expected size of GDT was 16 entries, but got %d.", gdt.entries);
      goto libtea_test_interrupts_cleanup;
    }
  }
  else{
    libtea_info("Test 1 failed: couldn't map GDT.");
    goto libtea_test_interrupts_cleanup;
  }

  libtea_info("Test 1 complete.\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 2: mapping IDT and checking CPL.");
  libtea_idt idt = {0};
  libtea_map_idt(instance, &idt);
  if(idt.base != MAP_FAILED){
    libtea_print_idt(&idt);
    if(idt.entries != 256){
      libtea_info("Test 2 failed: expected size of IDT was 256 entries, but got %d.", idt.entries);
      goto libtea_test_interrupts_cleanup;
    }
  }
  else{
    libtea_info("Test 2 failed: couldn't map IDT.");
    goto libtea_test_interrupts_cleanup;
  }
  int cpl = libtea_get_cpl();
  if(cpl != 3){
    libtea_info("Test 2 failed: libtea_get_cpl returned the wrong value, we should be in user space (CPL = 3).");
    goto libtea_test_interrupts_cleanup;
  }

  libtea_info("Test 2 complete.\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 3: custom user-mode interrupt handler for software interrupt.");
  libtea_ss_irq_count = 0;
  libtea_install_user_irq_handler(&idt, libtea_ss_irq_handler, LIBTEA_IRQ_VECTOR);
  generate_software_interrupt();
  if(libtea_ss_irq_count != 1){
    libtea_info("Test 3 failed: expected the custom interrupt handler to run once, but was run %d times.", libtea_ss_irq_count);
  }

  libtea_info("Test 3 complete.\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 4: custom kernel-mode interrupt handler for software interrupt.");

  libtea_info("Checking first that kernel mode execution is working before we try interrupts...");
  libtea_exec_in_kernel(instance, nop, ISOLATED_CPU_CORE);
  libtea_info("Back from kernel mode execution with CPL=%d (should be 3!).", libtea_get_cpl());
  libtea_info("Now trying custom interrupt handling in the kernel...");

  libtea_ss_irq_count = 0;
  libtea_install_kernel_irq_handler(&idt, libtea_ss_irq_handler, LIBTEA_IRQ_VECTOR);
  libtea_exec_in_kernel(instance, generate_software_interrupt, ISOLATED_CPU_CORE);
  libtea_info("Back from kernel execution and custom kernel interrupt handler with CPL=%d (should be 3!).", libtea_get_cpl());
  if(libtea_ss_irq_count != 1){
    libtea_info("Test 4 failed: expected the custom interrupt handler to run once, but was run %d times.", libtea_ss_irq_count);
  }

  libtea_info("Test 4 complete.\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 5: custom interrupt handler for APIC timer interrupt.");
  libtea_ss_irq_count = 0;
  libtea_apic_timer_oneshot(instance, LIBTEA_IRQ_VECTOR);
  generate_apic_timer_interrupt();
  if(libtea_ss_irq_count != 1){
    libtea_info("Test 5 failed: expected the custom interrupt handler to run once, but was run %d times.", libtea_ss_irq_count);
  }
  libtea_apic_timer_deadline(instance);

  libtea_info("Test 5 complete.\n");

  // ---------------------------------------------------------------------------

  libtea_unmap_address_range((size_t)idt.base, 4096);

  libtea_test_interrupts_cleanup:
  libtea_info("All tests complete, cleaning up...");
  libtea_cleanup(instance);
  libtea_info("Done!");
  return 0;
}


#ifdef __cplusplus
}
#endif
