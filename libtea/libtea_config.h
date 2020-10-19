
/* See LICENSE file for license and copyright information */

#ifndef _LIBTEA_CONFIG_H_
#define _LIBTEA_CONFIG_H_


/*
 * Set to 1 if your CPU supports Hyperthreading/SMT and it is enabled.
 */
#define LIBTEA_HAVE_HYPERTHREADING 1


/* Enable if your x86 CPU supports the RDTSCP instruction and you are running on
 * Linux (do not use on Windows - worse resolution than RDTSC). Has no effect on
 * non-x86 CPUs.
 */
#define LIBTEA_RDTSCP 1


/* The number of entries to use in the covert channel lookup table. This must be a
 * value between 1 and 256 inclusive. At 256, all possible values of a single byte
 * can be encoded. Consider reducing the value (e.g. to 26 to encode only 'A' to 'Z')
 * if testing on a CPU with a very small number of TLB entries, as the larger the
 * lookup table, the greater the pressure on the TLB. (You can also reduce the size of
 * the offset with the LIBTEA_COVERT_CHANNEL_OFFSET parameter below.)
 */
#define LIBTEA_COVERT_CHANNEL_ENTRIES 256


/* The offset to use between entries in the covert channel lookup table. This should be
 * a small power of 2 so multiplication with it will be compiled into a SHL instruction
 * (on x86, or equivalent otherwise). If this does not occur, attacks with very short
 * transient windows, such as ZombieLoad, will break. 4096 (page size) is typically the
 * best value on Intel CPUs; consider also 2056, 1024, or 4096*4 (observed to work well
 * on some Armv8-A and AMD CPUs).
 */
#define LIBTEA_COVERT_CHANNEL_OFFSET 4096


/* This enables the experimental libtea_isolate_windows_core function. If this is
 * enabled, you need to link with the PSAPI library (use -lpsapi) when compiling.
 * Warning: this is disabled by default because linking with this library seems to
 * increase the amount of cache noise, e.g. when using Libtea's cache covert channel
 * functions.
 */
#define LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION 0


/* This enables the experimental libtea_force_memory_deduplication function. If this
 * is enabled, you need to link with NTDLL (use -lntdll) when compiling.
 * Warning: this is disabled by default because linking with this library seems to
 * increase the amount of cache noise, e.g. when using Libtea's cache covert channel
 * functions.
 */
#define LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION 0


/*
 * Enabling this will disable all output of internal library messages to stdout.
 * Print functions explicitly called by the user will still print to stdout.
 */
#define LIBTEA_SILENT 0


/* Select which IRQ vector to use for your custom interrupt handler. Do not use values 0-31 (reserved for CPU exception handlers). */
#define LIBTEA_IRQ_VECTOR 45

/*
 * Configure APIC timer interval for next interrupt.
 *
 * NOTE: the exact timer interval value depends on the CPU frequency, and
 * hence remains inherently platform-specific. We empirically established
 * suitable timer intervals on the following platforms by tweaking and
 * observing the NOP microbenchmark erip results:
 *
 * Intel i7-6700 3.4GHz (Skylake), ucode unknown:        19
 * Intel i7-6500U 2.5GHz (Skylake), ucode unknown:       25
 * Intel i5-6200U 2.3GHz (Skylake), ucode unknown:       28
 * Intel i7-8650U 1.9GHz (Kaby Lake R), ucode unknown:   34
 * Intel i7-8650U 1.9GHz (Kaby Lake R), ucode 0xca:      54
 * Intel i9-9900K 3.6GHz (Coffee Lake R), ucode unknown: 21
 * Intel i5-1035G1 1GHz (Ice Lake), ucode 0x32:         135
 *
 * Please see the paper 'SGX-Step: A Practical Attack Framework for Precise
 * Enclave Execution Control' (Van Bulck et al., SysTEX 2017) and the
 * SGX-Step GitHub repository (https://github.com/jovanbulck/sgx-step) for
 * more details.
 *
 * Once you have established the correct timer interval for your platform,
 * uncomment #define LIBTEA_APIC_TIMER_INTERVAL below and insert the correct interval.
 */
//#define LIBTEA_APIC_TIMER_INTERVAL YOUR_VALUE_HERE
#ifndef LIBTEA_APIC_TIMER_INTERVAL
#if LIBTEA_SUPPORT_INTERRUPTS
  #ifdef _MSC_VER
  #pragma message ("You need to manually configure LIBTEA_APIC_TIMER_INTERVAL in libtea_config.h.")
  #else
  #warning You need to manually configure LIBTEA_APIC_TIMER_INTERVAL in libtea_config.h.
  #endif
#endif
#endif

#endif //_LIBTEA_CONFIG_H
