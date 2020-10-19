
/* See LICENSE file for license and copyright information */

/* Start libtea_ppc64_cache.c */
//---------------------------------------------------------------------------

#if LIBTEA_PPC

#include "libtea_arch.h"
#include <sys/platform/ppc.h>


int libtea__arch_init_cache_info(libtea_instance* instance){
 /* TODO any arch-defined ways to get PPC cache info? any assumptions we can make? */
 instance->llc_slices = instance->physical_cores;
 return 0; /* Report cache info is incomplete, parent function will parse from sysfs */
}


void libtea__arch_init_direct_physical_map(libtea_instance* instance){
  /* TODO replace with correct value for PPC64 */
  instance->direct_physical_map = 0x0ull;
}


void libtea__arch_init_eviction_strategy(libtea_instance* instance){
  /* TODO tune */
  instance->eviction_strategy.C = 2;
  instance->eviction_strategy.D = 5;
  instance->eviction_strategy.L = 2;
  instance->eviction_strategy.S = 30;
}


void libtea__arch_init_prime_strategy(libtea_instance* instance){
  instance->prime_strategy.C = 1;
  instance->prime_strategy.D = 2;
  instance->prime_strategy.L = 1;
  instance->prime_strategy.S = instance->llc_ways - instance->prime_strategy.D - 1;
}


void libtea__arch_fast_cache_encode(libtea_instance* instance, void* addr) {
  libtea_info("libtea_fast_cache_encode is unsupported on PPC64");
}


#endif //LIBTEA_PPC


/* End libtea_ppc64_cache.c */
//---------------------------------------------------------------------------
