
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_CACHE_H
#define LIBTEA_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libtea_common.h"
#include "module/libtea_ioctl.h"


/**
 * Performs Flush+Reload on the provided address and returns hit/miss based
 * on the current threshold.
 *
 * :param instance: The libtea instance
 * :param addr: The address
 * :return: 1 if the address was in the cache, 0 if the address was not cached
 */
libtea_inline int libtea_flush_reload(libtea_instance* instance, void* addr);


/**
 * Calibrates the threshold to distinguish between a cache hit and cache
 * miss using Flush+Reload.
 *
 * :param instance: The libtea instance
 */
libtea_inline void libtea_calibrate_flush_reload(libtea_instance* instance);


/**
 * Returns the cache slice of the provided physical address.
 * 
 * Note: only supported on Intel CPUs (based on Maurice et al., 'Reverse Engineering
 * Intel Last-Level Cache Complex Addressing Using Performance Counters', RAID 2015).
 * 
 * :param instance: The libtea instance
 * :param paddr: The physical address
 * :return: Cache slice of the physical address
 */
libtea_inline int libtea_get_cache_slice(libtea_instance* instance, size_t paddr);


/**
 * Returns the cache set of the provided physical address.
 *
 * :param instance: The libtea instance
 * :param paddr: The physical address
 * :return: Cache set of the physical address
 */
libtea_inline int libtea_get_cache_set(libtea_instance* instance, size_t paddr);


/**
 * Builds an eviction set for the provided physical address.
 *
 * :param instance: The libtea instance
 * :param set: The built eviction set
 * :param paddr: The physical address
 * :return: LIBTEA_SUCCESS on success, LIBTEA_ERROR otherwise
 */
libtea_inline int libtea_build_eviction_set(libtea_instance* instance, libtea_eviction_set* set, size_t paddr);


/**
 * Runs eviction using the provided eviction set.
 *
 * :param instance: The libtea instance
 * :param set: The eviction set
 */
libtea_inline void libtea_evict(libtea_instance* instance, libtea_eviction_set set);


/**
 * Performs Evict+Reload using the provided eviction set.
 * 
 * :param instance: The libtea instance
 * :param addr: The virtual address
 * :param set: The eviction set that should be used
 * :return: 1 if addr was cached
 */
libtea_inline int libtea_evict_reload(libtea_instance* instance, void* addr, libtea_eviction_set set);


/**
 * Calibrates the threshold to distinguish between a cache hit and cache
 * miss using Evict+Reload.
 *
 * :param instance: The libtea instance
 */
libtea_inline void libtea_calibrate_evict_reload(libtea_instance* instance);


/**
 * Performs the prime step using the provided eviction set.
 * 
 * :param instance: The libtea instance
 * :param set: The eviction set that should be used
 */
libtea_inline void libtea_prime(libtea_instance* instance, libtea_eviction_set set);


/**
 * Performs Prime+Probe and builds an eviction set for the provided address if
 * one does not exist.
 * 
 * :param instance: The libtea instance
 * :param set: The eviction set
 * :return: The execution time of the probe step
 */
libtea_inline int libtea_prime_probe(libtea_instance* instance, libtea_eviction_set set);


/**
 * Calculates the slice ID of the virtual address by measuring with performance counters (requires MSR access).
 * 
 * Note: only supported on Intel CPUs (based on Maurice et al., 'Reverse Engineering
 * Intel Last-Level Cache Complex Addressing Using Performance Counters', RAID 2015).
 *
 * :param instance: The libtea instance
 * :param vaddr: The virtual address
 * :return: The slice id
 */
libtea_inline size_t libtea_measure_slice(libtea_instance* instance, void* address);


/**
 * Encodes the provided value into the cache.
 *
 * :param instance: The libtea instance
 * :param value: The value to encode
 */
libtea_inline void libtea_cache_encode(libtea_instance* instance, unsigned char value);


/**
 * Dereferences a pointer at the provided offset and encodes the dereferenced value into the cache.
 * This function is intended for use with SCFirefox.
 *
 * :param instance: The libtea instance
 * :param ptr: The (char*) pointer to dereference
 * :param offset: The offset to dereference the pointer at (e.g. offset=10 -> ptr[10])
 */
libtea_inline void libtea_cache_encode_dereference(libtea_instance* instance, char* ptr, int offset);


/**
 * Like libtea_cache_encode_dereference, but uses optimized assembly to encode within an extremely short
 * transient window. Currently supported on x86 only.
 *
 * :param instance: The libtea instance
 * :param addr: The pointer to dereference
 */
#define libtea_fast_cache_encode(instance, addr) libtea__arch_fast_cache_encode(instance, addr)


/**
 * Decodes a value in a given range from the cache.
 * 
 * Note: you must ensure that the 'from' and 'to' values you specify do not exceed the value of
 * instance->covert_channel_entries (255 by default).
 *
 * :param instance: The libtea instance
 * :param from: The index in the covert channel to start decoding from (inclusive)
 * :param to: The index in the covert channel to stop decoding at (inclusive)
 * :param use_mix: Whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :return: The decoded value or LIBTEA_ERROR on error
 */
libtea_inline int libtea_cache_decode_from_to(libtea_instance* instance, int from, int to, bool use_mix);


/**
 * Decodes a value encoded into the cache covert channel.
 *
 * :param instance: The libtea instance
 * :param use_mix: Whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :return: The decoded value or LIBTEA_ERROR on error
 */
libtea_inline int libtea_cache_decode(libtea_instance* instance, bool use_mix);


/**
 * Decodes a value encoded into the cache covert channel (ignoring null/0).
 *
 * :param instance: The libtea instance
 * :param use_mix: Whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :return: The decoded value or LIBTEA_ERROR on error
 */
libtea_inline int libtea_cache_decode_nonull(libtea_instance* instance, bool use_mix);


/**
 * Decodes a value encoded into the cache covert channel and updates a histogram.
 *
 * :param instance: The libtea instance
 * :param use_mix: Whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :param print: Whether to output the updated histogram to stdout
 * :param offset: The value to add to the covert channel index to print the actual encoded character (if using <256 entries)
 * :param from: The index in the covert channel to start decoding from (inclusive)
 * :param to: The index in the covert channel to stop decoding at (inclusive)
 * :param hist: The histogram to modify (expects an int array with 256 elements)
 */
libtea_inline void libtea_cache_decode_histogram_iteration(libtea_instance* instance, bool use_mix, bool print, int offset, int from, int to, int* hist);


/**
 * Prints a histogram of decoded cache covert channel values to stdout for the provided
 * number of iterations. 
 * 
 * Note: this function repeatedly clears the terminal window.
 * 
 * :param instance: The libtea instance
 * :param iterations: The number of iterations to repeat for
 * :param sleep_len: The number of microseconds to sleep for between iterations (0 to not sleep)
 * :param yield: If true, call sched_yield() / SwitchToThread() between iterations
 * :param use_mix: Whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :param activity: A pointer to a function which should be called before each decode, e.g. a call to the victim (can be NULL to do nothing)
 * :param offset: The value to add to the covert channel index to get the actual encoded character (if using <256 entries)
 * :param from: The index in the covert channel to start decoding from (inclusive)
 * :param to: The index in the covert channel to stop decoding at (inclusive)
 */
libtea_inline void libtea_print_cache_decode_histogram(libtea_instance* instance, int iterations, int sleep_len, bool yield, bool use_mix, void(*activity)(), int offset, int from, int to);


/**
 * Returns a histogram of decoded cache covert channel values over the provided number
 * of iterations as an int array.
 * 
 * Note: the returned array is malloc'd and must be manually freed.
 * (size = sizeof(int) * LIBTEA_COVERT_CHANNEL_ENTRIES)
 * 
 * :param instance: The libtea instance
 * :param iterations: The number of iterations to repeat for
 * :param sleep_len: The number of microseconds to sleep for between iterations (0 to not sleep)
 * :param yield: If true, call sched_yield() / SwitchToThread() between iterations
 * :param use_mix: Whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
 * :param activity: A pointer to a function which should be called before each decode, e.g. a call to the victim (can be NULL to do nothing)
 * :param offset: The value to add to the covert channel index to get the actual encoded character (if using <256 entries)
 * :param from: The index in the covert channel to start decoding from (inclusive)
 * :param to: The index in the covert channel to stop decoding at (inclusive)
 */
libtea_inline int* libtea_numeric_cache_decode_histogram(libtea_instance* instance, int iterations, int sleep_len, bool yield, bool use_mix, void(*activity)(), int offset, int from, int to);


/*
 * Compares each decoded value with the expected value and returns the number of incorrect values.
 *
 * :param decoded: An array of values decoded from the cache covert channel
 * :param expected: An array of the expected/secret values
 * :param length: The length of the two arrays (must be equal)
 * :param print_results: If true, prints incorrect values and a success/fail summary to stdout, else runs silently
 * :return: The number of incorrect values
 */
int libtea_check_decoded(char* decoded, char* expected, int length, bool print_results);


/*
 * Calculates the percentage accuracy per decoded cache line (64 bytes) and prints the results
 * to stdout in CSV format.
 *
 * :param decoded: An array of values decoded from the cache covert channel
 * :param expected: An array of the expected/secret values
 * :param length: The length of the two arrays (must be equal)
 */
void libtea_check_decoded_per_cacheline(char* decoded, char* expected, int length);


/* Internal functions not included in API */
//---------------------------------------------------------------------------
libtea_inline static int libtea_init_cache(libtea_instance* instance);
libtea_inline static void libtea_cleanup_cache(libtea_instance* instance);


#define LIBTEA_ADDRESS_CACHE_SIZE (128)

#ifdef __cplusplus
}
#endif

#endif //LIBTEA_CACHE_H
