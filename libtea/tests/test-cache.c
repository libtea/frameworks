
/* See LICENSE file for license and copyright information */

#include "../libtea.h"
#include <inttypes.h>
#define TEST_CPU 1

int main(){

  libtea_instance* instance = libtea_init();
  if(!instance){
    libtea_info("Libtea test init failed.");
    return 1;
  }
  #if LIBTEA_LINUX
  libtea_pin_to_core(getpid(), TEST_CPU);
  #else
  libtea_pin_to_core(GetCurrentProcess(), TEST_CPU);
  #endif

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 1: Gathering info about vaddr.");

  char* addr = malloc(2);
  addr[0] = 'S';

  size_t paddr = libtea_get_physical_address(instance, (size_t)addr);
  if(paddr == LIBTEA_ERROR){
    libtea_info("Test 1 failed: can't get physical addresses. Try running with root privileges.");
    goto libtea_test_cache_cleanup;
  }

  int cache_slice = libtea_get_cache_slice(instance, paddr);
  int cache_set = libtea_get_cache_set(instance, paddr);
  size_t slice_id = libtea_measure_slice(instance, TEST_CPU, addr);

  libtea_info("Addr %p: physical address 0x%zx, cache slice (hash func) %d, cache slice (measured) %zu, cache set %d", addr, paddr, cache_slice, slice_id, cache_set);

  libtea_info("Test 1 complete.\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 2: Flush+Reload and decoding");

  libtea_calibrate_flush_reload(instance);
  libtea_info("Calibrated LLC miss threshold to %d", instance->llc_miss_threshold);

  unsigned char decoded_char_manual = 'A';
  unsigned char lut[256*4096];
  for(int i=0; i<256; i++){
    libtea_flush(lut + i * 4096);
  }
  libtea_speculation_barrier();
  libtea_access_b(lut + 'S' * 4096);

  for(int i=0; i<256; i++){
    if(libtea_flush_reload(instance, addr)){
      decoded_char_manual = 'S';
    }
  }

  for(int i=0; i<256; i++){
    libtea_flush(lut + i * 4096);
  }

  bool use_mix = false;    /* Change me if the cache tests fail */

  libtea_cache_encode(instance, 'S');
  unsigned char decoded_char = libtea_cache_decode(instance, use_mix);

  libtea_cache_encode(instance, 'S');
  unsigned char decoded_char_alpha = libtea_cache_decode_from_to(instance, 'A', 'Z', use_mix);

  libtea_cache_encode(instance, 'S');
  unsigned char decoded_char_no_null = libtea_cache_decode_nonull(instance, use_mix);

  if(decoded_char_manual != 'S' || decoded_char != 'S' || decoded_char_alpha != 'S' || decoded_char_no_null != 'S'){
    libtea_info("Test 2 failed: Flush+Reload covert channel decoded output was not correct. Retry with use_mix enabled - your CPU may need this.");
    libtea_info("Expecting S for all cases. Decoded: %c (manual), %c (auto), %c (auto from_to), %c (auto no null)", decoded_char_manual, decoded_char, decoded_char_alpha, decoded_char_no_null);
  }

  libtea_info("Test 2 complete.\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 3: Evict+Reload and Prime+Probe");

  libtea_calibrate_evict_reload(instance);
  libtea_info("Calibrated LLC miss threshold to %d", instance->llc_miss_threshold);

  libtea_eviction_set eviction_set;
  libtea_build_eviction_set(instance, &eviction_set, paddr);

  libtea_access_b(addr);
  sched_yield();
  if(libtea_evict_reload(instance, addr, eviction_set)){
    libtea_info("Evict+Reload: correctly detected a cache hit.");
  }
  else {
    libtea_info("Test 3 failed: Evict+Reload incorrectly claimed access was a cache miss.");
  }
  libtea_evict(instance, eviction_set);
  libtea_barrier_start();
  libtea_barrier_end();
  sched_yield();

  if(libtea_evict_reload(instance, addr, eviction_set)){
    libtea_info("Test 3 failed: Evict+Reload incorrectly claimed access was a cache hit.");
  }
  else libtea_info("Evict+Reload correctly detected a cache miss.");

  libtea_flush_b(addr);
  int miss_time = libtea_prime_probe(instance, eviction_set);
  printf("Time to prime for Prime+Probe is %d\n", miss_time);

  libtea_info("Test 3 complete.\n");

  // ---------------------------------------------------------------------------
  libtea_test_cache_cleanup:
  libtea_info("All tests complete, cleaning up...");
  free(addr);
  libtea_cleanup(instance);
  libtea_info("Done!");
  return 0;
}
