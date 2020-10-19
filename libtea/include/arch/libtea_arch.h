
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_ARCH_H
#define LIBTEA_ARCH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libtea_common.h"


/* Condition below will need adapting to support Windows on Arm, but MSVC is currently providing no helpful macros */
#if defined(__i386__) || defined(__x86_64__) || LIBTEA_WINDOWS
#define LIBTEA_X86 1
#elif defined(__aarch64__)
#define LIBTEA_AARCH64 1
#elif defined(__PPC64__) || defined(__ppc64__)
#define LIBTEA_PPC64 1
#endif


#if LIBTEA_LINUX || LIBTEA_INLINEASM
#define LIBTEA_NOP() asm volatile("nop")
#else
#define LIBTEA_NOP() __nop()
#endif

#if LIBTEA_LINUX
int libtea__arch_counting_thread(void* arg);
#else
DWORD WINAPI libtea__arch_counting_thread(LPVOID arg);
#endif


uint64_t libtea__arch_timestamp_native();
#if LIBTEA_X86
uint64_t libtea__arch_timestamp_native_amd_zen();
uint64_t libtea__arch_timestamp_native_amd_zen2();
#endif
uint64_t libtea__arch_timestamp_monotonic();
void libtea__trycatch_segfault_handler(int signum); /* Defined in libtea_common.c */
libtea_inline void libtea__arch_init_cpu_features(libtea_instance* instance);

#if LIBTEA_SUPPORT_CACHE
libtea_inline int libtea__arch_init_cache_info(libtea_instance* instance);
libtea_inline void libtea__arch_init_direct_physical_map(libtea_instance* instance);
libtea_inline void libtea__arch_init_eviction_strategy(libtea_instance* instance);
libtea_inline void libtea__arch_init_prime_strategy(libtea_instance* instance);
libtea_inline void libtea__arch_fast_cache_encode(libtea_instance* instance, void* addr);
#endif

libtea_inline int libtea__arch_transaction_begin();
libtea_inline void libtea__arch_transaction_end();
libtea_inline void libtea__arch_transaction_abort();


libtea_inline void libtea__arch_access(void* addr);


libtea_inline void libtea__arch_access_b(void* addr);


libtea_inline void libtea__arch_flush(void* addr);


libtea_inline void libtea__arch_flush_b(void* addr);


libtea_inline void libtea__arch_barrier_start();


libtea_inline void libtea__arch_barrier_end();


libtea_inline void libtea__arch_speculation_barrier();


libtea_inline int libtea__arch_write_system_reg(libtea_instance* instance, int cpu, uint32_t reg, uint64_t val);


libtea_inline size_t libtea__arch_read_system_reg(libtea_instance* instance, int cpu, uint32_t reg);


libtea_inline void libtea__arch_disable_hardware_prefetchers(libtea_instance* instance);


libtea_inline void libtea__arch_enable_hardware_prefetchers(libtea_instance* instance);


#ifdef __cplusplus
}
#endif

#endif //LIBTEA_ARCH_H
