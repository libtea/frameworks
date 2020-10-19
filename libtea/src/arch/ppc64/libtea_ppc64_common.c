
/* See LICENSE file for license and copyright information */

/* Start libtea_ppc64_common.c */
//---------------------------------------------------------------------------

#if LIBTEA_PPC

#include "libtea_arch.h"
#include <sys/platform/ppc.h>
#include <htmintrin.h>   /* Need to compile with GCC flag -mhtm */

int libtea__arch_counting_thread(void* arg) {
  /* Note: libtea threads cannot use libc functions! */
  volatile size_t* counter = (volatile size_t*)arg;
  size_t count = 0;
  while(1) {
    count++;
    *counter = count;
  }
}


libtea_inline uint64_t libtea__arch_timestamp_native() {
  asm volatile("lwsync");
  uint64_t time;
  asm volatile("mfspr %0, 268" : "=r" (time) : :); /* No point using __ppc_get_timebase() because this is all it does. But we could use __ppc_get_timebase_freq() to adjust for varying frequency */
  asm volatile("lwsync");
  return time;
}


libtea_inline uint64_t libtea__arch_timestamp_monotonic() {
  asm volatile("lwsync");
  struct timespec t1;
  clock_gettime(CLOCK_MONOTONIC, &t1);
  uint64_t res = t1.tv_sec * 1000 * 1000 * 1000ULL + t1.tv_nsec;
  asm volatile("lwsync");
  return res;
}


void libtea__arch_init_cpu_features(libtea_instance* instance){
  instance->is_intel = 0;
  /* 
   * TODO need to implement a check for hardware transactional memory support. Currently we just assume it's present
   * on all PowerPC.
   */
  instance->has_tm = 1;
  /* Any future CPU checks should be added here */
}


libtea_inline int libtea__arch_transaction_begin(){
  return __builtin_tbegin(0);
}


libtea_inline void libtea__arch_transaction_end(){
  __builtin_tend(0);
}


libtea_inline void libtea__arch_transaction_abort(){
  __builtin_tabort(0);
}


libtea_inline void libtea__arch_access(void* addr) {
  asm volatile( "ld %%r0, 0(%0)" ::"r"(addr): "r0");
}


libtea_inline void libtea__arch_access_b(void* addr) {
  asm volatile("lwsync");
  asm volatile( "ld %%r0, 0(%0)" ::"r"(addr): "r0");
  asm volatile("lwsync");
}


libtea_inline void libtea__arch_prefetch(void* addr){
  asm volatile ("dcbt 0, %0" : : "r" (addr));
}


libtea_inline void libtea__arch_prefetchw(void* addr){
  asm volatile ("dcbtst 0, %0" : : "r" (addr));
}


libtea_inline void libtea__arch_flush(void* addr) {
  asm volatile("dcbf 0, %0" :  : "r"(addr) :);
	asm volatile("dcs");
  asm volatile("ics");
}


libtea_inline void libtea__arch_flush_b(void* addr) {
  asm volatile("lwsync");
  asm volatile("dcbf 0, %0" :  : "r"(addr) :);
	asm volatile("dcs");
  asm volatile("ics");
  asm volatile("lwsync");
}


libtea_inline void libtea__arch_barrier_start() {
  asm volatile("lwsync");
}


libtea_inline void libtea__arch_barrier_end() {
  asm volatile("lwsync");
}


libtea_inline void libtea__arch_speculation_barrier() {
  asm volatile("hwsync");
}


#if LIBTEA_INLINEASM
#define libtea__arch_speculation_start(label) libtea_info("libtea__arch_start_speculation is not implemented on PPC64 yet.");
#define libtea__arch_speculation_end(label) libtea_info("libtea__arch_end_speculation is not implemented on PPC64 yet.");
#endif


int libtea__arch_write_system_reg(libtea_instance* instance, int cpu, uint32_t reg, uint64_t val) {
  libtea_info("Reading and writing system registers on PPC64 is not implemented yet.");
  return LIBTEA_ERROR;
}


size_t libtea__arch_read_system_reg(libtea_instance* instance, int cpu, uint32_t reg) {
  libtea_info("Reading and writing system registers on PPC64 is not implemented yet.");
  return LIBTEA_ERROR;
}


void libtea__arch_disable_hardware_prefetchers(libtea_instance* instance) {
  libtea_info("Disabling prefetchers is not supported on this platform.");
}


void libtea__arch_enable_hardware_prefetchers(libtea_instance* instance) {
  libtea_info("Disabling prefetchers is not supported on this platform.");
}

#endif //LIBTEA_PPC


/* End libtea_ppc64_common.c */
//---------------------------------------------------------------------------