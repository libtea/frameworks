
/* See LICENSE file for license and copyright information */

/* Start libtea_aarch64_common.c */
//---------------------------------------------------------------------------

#if LIBTEA_AARCH64

#include "libtea_arch.h"


int libtea__arch_counting_thread(void* arg) {
  /* Note: libtea threads cannot use libc functions! */
  volatile size_t* counter = (volatile size_t*)arg;
  size_t count = 0;
  while(1) {
    count++;
    *counter = count;
  }
  return 0;
}


libtea_inline uint64_t libtea__arch_timestamp_native() {
  uint64_t result = 0;
  asm volatile("DSB SY; ISB; MRS %0, PMCCNTR_EL0; ISB" : "=r"(result));
  return result;
}


libtea_inline uint64_t libtea__arch_timestamp_monotonic() {
  asm volatile("DSB SY");
  struct timespec t1;
  clock_gettime(CLOCK_MONOTONIC, &t1);
  uint64_t res = t1.tv_sec * 1000 * 1000 * 1000ULL + t1.tv_nsec;
  asm volatile("ISB; DSB SY");
  return res;
}


void libtea__arch_init_cpu_features(libtea_instance* instance){
  instance->is_intel = 0;
  /* Any future CPU checks should be added here, e.g. checking for hardware transactional memory support */
}


libtea_inline int libtea__arch_transaction_begin(){
  libtea_info("BUG: no transactional memory support implemented for AArch64, this function should not be running");
  return 0;
}


libtea_inline void libtea__arch_transaction_end(){
  libtea_info("BUG: no transactional memory support implemented for AArch64, this function should not be running");
}


libtea_inline void libtea__arch_transaction_abort(){
  libtea_info("BUG: no transactional memory support implemented for AArch64, this function should not be running");
}


libtea_inline void libtea__arch_access(void* addr) {
  volatile uint32_t value;
  asm volatile("LDR %w0, [%1]" : "=r"(value) : "r"(addr));
}


libtea_inline void libtea__arch_access_b(void* addr) {
  volatile uint32_t value;
  asm volatile("ISB; DSB ISH; LDR %w0, [%1]; DSB ISH; ISB" : "=r"(value) : "r"(addr));
}


libtea_inline void libtea__arch_prefetch(void* addr){
  libtea_info("Prefetch is not supported on Libtea for Aarch64 yet.");
}


libtea_inline void libtea__arch_prefetchw(void* addr){
  libtea_info("Prefetch is not supported on Libtea for Aarch64 yet.");
}


libtea_inline void libtea__arch_flush(void* addr) {
  asm volatile("DC CIVAC, %0" ::"r"(addr));
}


libtea_inline void libtea__arch_flush_b(void* addr) {
  asm volatile("ISB; DSB ISH; DC CIVAC, %0; DSB ISH; ISB" ::"r"(addr));
}


libtea_inline void libtea__arch_barrier_start() {
  asm volatile("DSB ISH; ISB");
}


libtea_inline void libtea__arch_barrier_end() {
  asm volatile("ISB; DSB ISH");
}


libtea_inline void libtea__arch_speculation_barrier() {
  asm volatile("DSB SY; ISB");
}


#if LIBTEA_INLINEASM
#define libtea__arch_speculation_start(label) libtea_info("libtea__arch_start_speculation is not implemented on Aarch64 yet.");
#define libtea__arch_speculation_end(label) libtea_info("libtea__arch_end_speculation is not implemented on Aarch64 yet.");
#endif


int libtea__arch_write_system_reg(libtea_instance* instance, int cpu, uint32_t reg, uint64_t val) {
  #if LIBTEA_LINUX
  if(instance->module_fd <= 0){
  #else
  if(instance->module_fd == NULL){
  #endif
    libtea_info("The libtea driver must be loaded to read and write system registers.");
    return LIBTEA_ERROR;
  }
    
  #if LIBTEA_LINUX 
  ioctl(instance->module_fd, LIBTEA_IOCTL_SET_SYSTEM_REG, cpu, reg, val);
    
  #else
  DWORD returnLength;
  size_t info[3];
  info[0] = cpu;
  info[1] = reg;
  info[2] = val;  /* Assuming size_t is 64-bit, true on 64-bit Windows */
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_SET_SYSTEM_REG, (LPVOID)info, sizeof(info), (LPVOID)info, sizeof(info), &returnLength, 0);
  #endif

  return LIBTEA_SUCCESS;
}


size_t libtea__arch_read_system_reg(libtea_instance* instance, int cpu, uint32_t reg) {
  #if LIBTEA_LINUX
  if(instance->module_fd <= 0){
  #else 
  if(instance->module_fd == NULL){
  #endif
    libtea_info("The libtea driver must be loaded to read and write system registers.");
    return LIBTEA_ERROR;
  }
    
  #if LIBTEA_LINUX 
  libtea_system_reg msr_info;
  msr_info.cpu = cpu;
  msr_info.reg = reg;
  msr_info.val = 0;
  ioctl(instance->module_fd, LIBTEA_IOCTL_GET_SYSTEM_REG, &msr_info);
  return msr_info.val;
    
  #else
  DWORD returnLength;
  size_t info[3];
  info[0] = cpu;
  info[1] = reg;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_GET_SYSTEM_REG, (LPVOID)info, sizeof(info), (LPVOID)info, sizeof(info), &returnLength, 0);
  /* TODO return value is returned by overwriting info, assume for now it is first value */
  return info[0];
  #endif
}


void libtea__arch_disable_hardware_prefetchers(libtea_instance* instance) {
  libtea_info("Disabling prefetchers is not supported on this platform.");
}


void libtea__arch_enable_hardware_prefetchers(libtea_instance* instance) {
  libtea_info("Disabling prefetchers is not supported on this platform.");
}


#endif //LIBTEA_AARCH64


/* End libtea_aarch64_common.c */
//---------------------------------------------------------------------------
