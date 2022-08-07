
/* See LICENSE file for license and copyright information */

/* Start libtea_x86_common.c */
//---------------------------------------------------------------------------

#if LIBTEA_X86

#include "libtea_arch.h"
#include <inttypes.h>

#if LIBTEA_LINUX
#include <cpuid.h>
#include <sys/utsname.h>
#endif

#define RDPRU ".byte 0x0f, 0x01, 0xfd"

#if LIBTEA_LINUX
int libtea__arch_counting_thread(void* arg) {
#else
DWORD WINAPI libtea__arch_counting_thread(LPVOID arg) {
#endif

  #if LIBTEA_INLINEASM
  /* Note: libtea threads cannot use libc functions! */
  volatile size_t* counter = (volatile size_t*)arg;
  asm volatile("1: inc %%rax\n"
                "mov %%rax, (%%rcx)\n"
                "jmp 1b" : : "c"(counter), "a"(0));

  #else
  libtea__windows_counting_thread(arg);
  #endif

  return 0;
}


libtea_inline uint64_t libtea__arch_timestamp_native() {

  #if LIBTEA_INLINEASM
  uint64_t a, d;
  asm volatile("mfence");
  #if LIBTEA_RDTSCP
  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
  #else
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  #endif
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;

  #else
  unsigned int tsc_aux;
  _mm_mfence();
  #if LIBTEA_RDTSCP
  uint64_t time = __rdtscp(&tsc_aux);
  #else
  uint64_t time = __rdtsc();
  #endif
  _mm_mfence();
  return time;
  #endif

}


libtea_inline uint64_t libtea__arch_timestamp_native_amd_zen() {
  /* TODO - read from kernel driver */
  uint64_t dummy = 0;
  return dummy;
}


libtea_inline uint64_t libtea__arch_timestamp_native_amd_zen2() {
  uint64_t low = 0;
  uint64_t high = 0;
  
  #if LIBTEA_INLINEASM
  asm volatile("mfence");
  asm volatile(RDPRU
			     : "=a" (low), "=d" (high)
			     : "c" (1));
  asm volatile("mfence");
  
  #else
  //TODO libtea__windows_rdpru(low, high);
  high = 0;
  #endif

  high = (high << 32) | low;
  return high;
}


libtea_inline uint64_t libtea__arch_timestamp_monotonic() {

  #if LIBTEA_LINUX
  asm volatile("mfence");
  struct timespec t1;
  clock_gettime(CLOCK_MONOTONIC, &t1);
  uint64_t res = t1.tv_sec * 1000 * 1000 * 1000ULL + t1.tv_nsec;
  asm volatile("mfence");
  return res;

  #else
  //TODO replace - now using QPC in perf timer instead
  LARGE_INTEGER time;
  QueryPerformanceCounter(&time);
  return (uint64_t) time.QuadPart;
  #endif

}


void libtea__arch_init_cpu_features(libtea_instance* instance){

    /* CPU manufacturer ID string (12 ASCII chars) is returned in EBX, EDX,
     * ECX (in that order, which is why we need to reorder the array in
     * 'name'). The largest value that EAX can be set to before calling
     * cpuid (which can be used to identify Intel microarchitectures) is
     * returned in EAX.
     */
    #if LIBTEA_LINUX
    uint32_t name[4] = {0, 0, 0, 0};
    __cpuid(0, instance->cpu_architecture, name[0], name[2], name[1]);
    if(strcmp((char *) name, "GenuineIntel") == 0) {
      instance->is_intel = 1;
      /* Check for Intel TSX */
      if (__get_cpuid_max(0, NULL) >= 7) {
        uint32_t a, b, c, d;
        __cpuid_count(7, 0, a, b, c, d);
        instance->has_tm = (b & (1 << 11)) ? 1 : 0;
      }
    }
    else instance->is_intel = 0;

    #else
    int temp[4] = {0, 0, 0, 0};
    __cpuid(temp, 0);
    int name[4] = {0, 0, 0, 0};
    name[0] = temp[1];
    name[1] = temp[3];
    name[2] = temp[2];
    instance->cpu_architecture = temp[0]; 
    if(strcmp((char *) name, "GenuineIntel") == 0) {
      instance->is_intel = 1;
      if (temp[0] >= 7) {
        /* Check for Intel TSX: EAX=7, ECX=0; returned value in EBX */
        __cpuidex(temp, 7, 0);
        instance->has_tm = (temp[1] & (1 << 11)) ? 1 : 0;
      }
    }
    else{
      instance->is_intel = 0;
      instance->has_tm = 0;
    }
    #endif
}


libtea_inline int libtea__arch_transaction_begin(){

  #if LIBTEA_INLINEASM
  int ret = (~0u);
  asm volatile(".byte 0xc7,0xf8 ; .long 0" : "+a" (ret) :: "memory");
  return ret == (~0u);

  #else
  return _xbegin();
  #endif

}


libtea_inline void libtea__arch_transaction_end(){
  #if LIBTEA_INLINEASM
  asm volatile(".byte 0x0f; .byte 0x01; .byte 0xd5" ::: "memory");  /* TSX xend */
  #else
  _xend();
  #endif
}


libtea_inline void libtea__arch_transaction_abort(){
  #if LIBTEA_INLINEASM
  asm volatile(".byte 0xc6; .byte 0xf8; .byte 0x00" ::: "memory");  /* TSX xabort(0) */
  #else
  _xabort(0);
  #endif
}


libtea_inline void libtea__arch_access(void* addr) {

  #if LIBTEA_INLINEASM
  asm volatile("movq (%0), %%rax\n" : : "r"(addr) : "rax");

  #else
  volatile char* access = (char*) addr;
  volatile char dummy = access[0];
  #endif

}


libtea_inline void libtea__arch_access_b(void* addr) {

  #if LIBTEA_INLINEASM
  asm volatile("mfence");
  asm volatile("movq (%0), %%rax\n" : : "r"(addr) : "rax");
  asm volatile("mfence");

  #else
  _mm_mfence();
  volatile char* access = (char*) addr;
  volatile char dummy = access[0];
  _mm_mfence();
  #endif

}


libtea_inline void libtea__arch_prefetch(void* addr){

  #if LIBTEA_INLINEASM
  asm volatile ("prefetcht0 (%0)" : : "r" (addr));
  /* Options:
   * prefetcht0 (temporal data)—prefetch data into all levels of the cache hierarchy.
   * prefetcht1 (temporal data with respect to first level cache misses)—prefetch data into level 2 cache and higher.
   * prefetcht2 (temporal data with respect to second level cache misses)—prefetch data into level 3 cache and higher, or an implementation-specific choice.
   * prefetchnta (non-temporal data with respect to all cache levels)—prefetch data into non-temporal cache structure and into a location close to the processor, minimizing cache pollution.
   */
  #else
  _m_prefetch(addr);
  #endif

}


libtea_inline void libtea__arch_prefetchw(void* addr){
  
  #if LIBTEA_INLINEASM
  asm volatile ("prefetchw (%0)" : : "r" (addr));
  #else
  _m_prefetchw(addr);
  #endif

}


libtea_inline void libtea__arch_flush(void* addr) {

  #if LIBTEA_INLINEASM
  asm volatile("clflush 0(%0)\n" : : "c"(addr) : "rax");
  
  #else
  _mm_clflush(addr);
  #endif

}


libtea_inline void libtea__arch_flush_b(void* addr) {

  #if LIBTEA_INLINEASM
  asm volatile("mfence");
  asm volatile("clflush 0(%0)\n" : : "r"(addr) : "rax");
  asm volatile("mfence");
  
  #else
  _mm_mfence();
  _mm_clflush(addr);
  _mm_mfence();
  #endif

}


libtea_inline void libtea__arch_barrier_start() {

  #if LIBTEA_INLINEASM
  asm volatile("mfence");
  
  #else
  _mm_mfence();
  #endif

}


libtea_inline void libtea__arch_barrier_end() {
  
  #if LIBTEA_INLINEASM
  asm volatile("mfence");
  
  #else
  _mm_mfence();
  #endif

}


libtea_inline void libtea__arch_speculation_barrier() {
  /* Even though lfence is not fully serializing, we use it as a 
   * compromise due to the variable latency and weak uop ordering
   * guarantees of cpuid. See 'nanoBench: A Low-Overhead
   * Tool for Running Microbenchmarks on x86 Systems' for discussion.
   */

  #if LIBTEA_INLINEASM
  asm volatile("lfence");

  #else
  _mm_lfence();
  #endif

}


#if LIBTEA_INLINEASM
#define libtea__arch_speculation_start(label) asm goto ("call %l0" : : : "memory" : label##_retp);
#define libtea__arch_speculation_end(label) asm goto("jmp %l0" : : : "memory" : label); label##_retp: asm goto("lea %l0(%%rip), %%rax; movq %%rax, (%%rsp); ret" : : : "memory","rax" : label); label: asm volatile("nop");
#endif


int libtea__arch_write_system_reg(libtea_instance* instance, int cpu, uint32_t reg, uint64_t val) {

  #if LIBTEA_LINUX
  char msr_file_name[64];
  sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);

  int fd = open(msr_file_name, O_WRONLY);
  if(fd < 0) {
    libtea_info("msr driver not loaded, will try with Libtea driver.");
    goto libtea_write_system_reg_driver;
  }

  if(pwrite(fd, &val, sizeof(val), reg) != sizeof(val)) {
      close(fd);
      libtea_info("Failed to read MSR with msr driver!");
      return LIBTEA_ERROR;
  }

  close(fd);
  return LIBTEA_SUCCESS;
  #endif

  #if LIBTEA_LINUX
  libtea_write_system_reg_driver:
    if(instance->module_fd <= 0){
    #else
    if(instance->module_fd == NULL){
    #endif
      libtea_info("Either the msr driver or the Libtea driver must be loaded to read and write system registers.");
      return LIBTEA_ERROR;
    }

    #if LIBTEA_LINUX
    ioctl(instance->module_fd, LIBTEA_IOCTL_SET_SYSTEM_REG, cpu, reg, val);

    #else
    DWORD returnLength;
    libtea_system_reg msr_info;
    msr_info.cpu = cpu;
    msr_info.reg = reg;
    msr_info.val = val;
    DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_SET_SYSTEM_REG, (LPVOID)&msr_info, sizeof(libtea_system_reg), (LPVOID)&msr_info, sizeof(libtea_system_reg), &returnLength, 0);
    #endif

    return LIBTEA_SUCCESS;
}


size_t libtea__arch_read_system_reg(libtea_instance* instance, int cpu, uint32_t reg) {

  #if LIBTEA_LINUX
  size_t data = 0;
  char msr_file_name[64];
  sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);

  int fd = open(msr_file_name, O_RDONLY);
  if(fd < 0) {
    libtea_info("msr driver not loaded, will try with libtea driver.");
    goto libtea_read_system_reg_driver;
  }

  if(pread(fd, &data, sizeof(data), reg) != sizeof(data)) {
      close(fd);
      libtea_info("Failed to read MSR with msr driver!");
      return SIZE_MAX;		// Cannot return LIBTEA_ERROR as size_t is unsigned
  }
  close(fd);
  return data;
  #endif

  #if LIBTEA_LINUX
  libtea_read_system_reg_driver:
    if(instance->module_fd <= 0){
    #else
    if(instance->module_fd == NULL){
    #endif
      libtea_info("Either the msr driver or the libtea driver must be loaded to read and write system registers.");
      return SIZE_MAX;
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
    libtea_system_reg msr_info;
    msr_info.cpu = cpu;
    msr_info.reg = reg;
    msr_info.val = 0;
    DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_GET_SYSTEM_REG, (LPVOID)&msr_info, sizeof(libtea_system_reg), (LPVOID)&msr_info, sizeof(libtea_system_reg), &returnLength, 0);
    return msr_info.val;
    #endif

}


void libtea__arch_disable_hardware_prefetchers(libtea_instance* instance) {
  if(instance->is_intel) {
    for(int i = 0; i < instance->logical_cores; i++) {
        libtea_write_system_reg(instance, i, 0x1a4, 0xf);
    }
  }
  else libtea_info("Disabling prefetchers is only implemented for Intel CPUs.");
  /* MSRs to control this are undocumented on AMD Zen, unsure on Via */
}


void libtea__arch_enable_hardware_prefetchers(libtea_instance* instance) {
  if(instance->is_intel) {
    for(int i = 0; i < instance->logical_cores; i++) {
        libtea_write_system_reg(instance, i, 0x1a4, 0x0);
    }
  }
  else libtea_info("Disabling prefetchers is only implemented for Intel CPUs.");
  /* MSRs to control this are undocumented on AMD Zen, unsure on Via */
}

#endif //LIBTEA_X86


/* End libtea_x86_common.c */
//---------------------------------------------------------------------------
