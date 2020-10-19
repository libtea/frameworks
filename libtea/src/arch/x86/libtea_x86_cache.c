
/* See LICENSE file for license and copyright information */

/* Start libtea_x86_cache.c */
//---------------------------------------------------------------------------

#if LIBTEA_X86

#include "libtea_arch.h"


int libtea__arch_init_cache_info(libtea_instance* instance){
  instance->llc_slices = instance->physical_cores;    /* This holds on Intel (exception handled below) and AMD Zen -> Epyc, Zen 2 */
  
  int level = 0;
  uint32_t eax, ebx, ecx, edx;

  if(instance->is_intel) {
    if(instance->cpu_architecture >= 0x16) { 
      /* If Skylake or newer */
      instance->llc_slices *= 2;
    }
    do {
      
      #if LIBTEA_LINUX
      asm volatile("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (4), "c" (level));
      #else
      int cpuid_info[4] = {0, 0, 0, 0};
      __cpuidex(cpuid_info, 4, level);
      eax = cpuid_info[0];
      ebx = cpuid_info[1];
      ecx = cpuid_info[2];
      edx = cpuid_info[3];
      #endif
      
      int type = eax & 0x1f;
      if(!type) break;
      level++;
      instance->llc_line_size = (ebx & 0xfff) + 1;
      instance->llc_ways = ((ebx >> 22) & 0x3ff) + 1;
      instance->llc_sets = ecx + 1;
      instance->llc_partitions = ((ebx >> 12) & 0x3ff) + 1;
      instance->llc_size = instance->llc_line_size * instance->llc_ways * instance->llc_sets * instance->llc_partitions;
    } while(1);
    return 1;    /* Report cache data is complete */
  }

  /* Check if it is actually an AMD CPU and not Via, Centaur etc */
  
  #if LIBTEA_LINUX
  uint32_t temp = 0;
  uint32_t name[3] = {0, 0, 0};
  __cpuid(0, temp, name[0], name[2], name[1]);
  if(strcmp((char *) name, "AuthenticAMD") == 0) {
  
  #else
  int temp[4] = {0, 0, 0, 0};
  __cpuid(temp, 0);
  int name[4] = {0, 0, 0, 0};
  name[0] = temp[1];
  name[1] = temp[3];
  name[2] = temp[2];
  if(strcmp((char *) name, "AuthenticAMD") == 0) {
  #endif

    do {
    
      #if LIBTEA_LINUX
      asm volatile("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0x8000001D), "c" (level));
      #else
      int cpuid_info[4] = {0, 0, 0, 0};
      __cpuidex(cpuid_info, 0x8000001D, level);
      eax = cpuid_info[0];
      ebx = cpuid_info[1];
      ecx = cpuid_info[2];
      edx = cpuid_info[3];
      #endif
      
      int type = eax & 0xf;   /* bits 4:0 */
      if(!type && level == 0){
        /* If this happens, the CPU does not support CPUID topology extensions */
        return 0;
      }
      else if(!type) break;
      level++;
      instance->llc_line_size = (ebx & 0xfff) + 1;            /* Bits 11:0 of EBX */
      instance->llc_partitions = ((ebx >> 12) & 0x3ff) + 1;   /* Bits 21:12 of EBX */
      instance->llc_ways = ((ebx >> 22) & 0x3ff) + 1;         /* Bits 31:22 of EBX */
      instance->llc_sets = ecx + 1;
      instance->llc_size = instance->llc_line_size * instance->llc_ways * instance->llc_sets * instance->llc_partitions;
    } while(1);

    return 1;    /* Report cache data is complete */
  }

  else return 0; /* Report cache data is incomplete - parent function will parse from sysfs instead */
}


void libtea__arch_init_direct_physical_map(libtea_instance* instance){

  #if LIBTEA_LINUX
  struct utsname buf;
  uname(&buf);
  int major = atoi(strtok(buf.release, "."));
  int minor = atoi(strtok(NULL, "."));

  if((major == 4 && minor < 19) || major < 4) {
    instance->direct_physical_map = 0xffff880000000000ull;
  } else {
    instance->direct_physical_map = 0xffff888000000000ull;
  }
  #else
  /* No direct-physical map on Windows */
  instance->direct_physical_map = 0;
  #endif

}


void libtea__arch_init_eviction_strategy(libtea_instance* instance){
  instance->eviction_strategy.C = 4;
  instance->eviction_strategy.D = 5;
  instance->eviction_strategy.L = 5;
  instance->eviction_strategy.S = 20;
}


void libtea__arch_init_prime_strategy(libtea_instance* instance){
  instance->prime_strategy.C = 1;
  instance->prime_strategy.D = 2;
  instance->prime_strategy.L = 1;
  instance->prime_strategy.S = instance->llc_ways - instance->prime_strategy.D - 1;
}


void libtea__arch_fast_cache_encode(libtea_instance* instance, void* addr) {
  #if LIBTEA_INLINEASM
  asm volatile("movzx (%%rcx), %%rax; shl $12, %%rax; movq (%%rbx,%%rax,1), %%rbx" : : "c"(addr), "b"(instance->covert_channel) : "rax");
  #else
  libtea_info("libtea_fast_cache_encode is not supported when compiled without inline assembly support");
  #endif
}


#endif //LIBTEA_X86


/* End libtea_x86_cache.c */
//---------------------------------------------------------------------------
