
/* See LICENSE file for license and copyright information */

#ifdef __cplusplus
extern "C" {
#endif

#include "../libtea.h"
#include <inttypes.h>

int main(int argc, char **argv){

  libtea_instance* instance = libtea_init();

  if(!instance){
    libtea_info("Libtea test init failed.");
    return 1;
  }

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 1: flushes, accesses, timing, and barriers.");
  char* addr = malloc(2);
  libtea_file sharedMemHandle;
  char* mem = libtea_open_shared_memory(4096, &sharedMemHandle);
  libtea_access(mem);
  libtea_close_shared_memory(mem, &sharedMemHandle, 4096);
  addr[0] = 'S';
  uint64_t timestamp = 0;
  libtea_access(addr);

  for(int i=0; i<5; i++){
    /* On first iteration we don't manually set the timer to test if it's initialized to a valid value */
    if(i==1){
      libtea_info("Testing with native timer...");
      libtea_set_timer(instance, LIBTEA_TIMER_NATIVE);
    }
    else if(i==2){
      libtea_set_timer(instance, LIBTEA_TIMER_COUNTING_THREAD);
      libtea_info("Testing with counting thread...");
    }
    else if(i==3){
      libtea_set_timer(instance, LIBTEA_TIMER_PERF);
      libtea_info("Testing with perf (if this returns 0, try running with sudo)...");
    }
    else if(i==4){
      libtea_set_timer(instance, LIBTEA_TIMER_MONOTONIC_CLOCK);
      libtea_info("Testing with counting thread...");
    }

    libtea_speculation_barrier();
    libtea_barrier_start();
    libtea_measure_start(instance);
    libtea_access(addr);
    timestamp = libtea_timestamp(instance);
    libtea_measure_end(instance);
    libtea_barrier_end();
    libtea_info("Timestamp is %" PRIu64 "", timestamp);

    libtea_speculation_barrier();
    libtea_barrier_start();
    libtea_measure_start(instance);
    libtea_access(addr);
    timestamp = libtea_measure_end(instance);
    libtea_barrier_end();
    libtea_info("Cache hit time with libtea_measure_end is %" PRIu64 "", timestamp);

    libtea_flush(addr);
    libtea_speculation_barrier();
    libtea_barrier_start();
    libtea_measure_start(instance);
    libtea_access(addr);
    timestamp = libtea_measure_end(instance);
    libtea_barrier_end();
    libtea_info("Cache miss time is %" PRIu64 "", timestamp);

    libtea_speculation_barrier();
    libtea_measure_start(instance);
    libtea_access_b(addr);
    timestamp = libtea_measure_end(instance);
    libtea_speculation_barrier();
    libtea_info("Cache hit time (barrier) is %" PRIu64 "", timestamp);

    libtea_flush_b(addr);
    libtea_speculation_barrier();
    libtea_measure_start(instance);
    libtea_access_b(addr);
    timestamp = libtea_measure_end(instance);
    libtea_speculation_barrier();
    libtea_info("Cache miss time (barrier) is %" PRIu64 "\n", timestamp);

  }

  libtea_timestamp(instance);

  /* Success criteria: application didn't crash! Manually check timings are plausible */
  libtea_info("Test 1 passed.\n\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 2: try/catch blocks (transactional memory / exception handling).");

  libtea_info("Trying with signal handling...");

  libtea_try_start() {
    libtea_access(0);
  }
  libtea_try_end();

  libtea_try_start() {
    libtea_try_abort();
  }
  libtea_try_end();

  if(instance->has_tm){
    libtea_info("Trying with transactional memory...");

    libtea_try_start_tm() {
      libtea_access(0);
    }

    libtea_try_start_tm() {
      libtea_try_abort_tm();
    }
  }
  else libtea_info("Not trying with transactional memory, because your system does not seem to support it.");

  #if LIBTEA_INLINEASM
  libtea_info("Trying with specpoline...");
  libtea_speculation_start(specpoline);
    libtea_access(0);
  libtea_speculation_end(specpoline);
  #else
  libtea_info("Skipping specpoline test because inline assembly is not supported by this compiler.");
  #endif

  /* Success criteria: application didn't crash! */
  libtea_info("Test 2 passed.\n\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 3: core pinning and hyperthreads.");

  /* Try to pin to core 0 and check we actually are now running on core 0 */
  #if LIBTEA_LINUX && defined(__CPU_SETSIZE) && defined(__NCPUBITS)
  libtea_pin_to_core(getpid(), 0);
  cpu_set_t expected_mask;
  cpu_set_t actual_mask;
  CPU_ZERO(&expected_mask);
  CPU_ZERO(&actual_mask);
  CPU_SET(0, &expected_mask);
  sched_getaffinity(0, sizeof(actual_mask), &actual_mask);
  for(int i=0; i<__CPU_SETSIZE / __NCPUBITS; i++){
    if(expected_mask.__bits[i] != actual_mask.__bits[i]){
      libtea_info("Test 3 failed, failed to pin to core 0.");
      goto libtea_test_basic_cleanup;
    }
  }

  /* Query hyperthread of core 0 */
  int hyperthread = libtea_get_hyperthread(0);
  if(hyperthread == LIBTEA_ERROR){
    libtea_info("Test 3 failed, could not get hyperthread of core 0.");
    goto libtea_test_basic_cleanup;
  }
  else libtea_info("Hyperthread of core 0 is logical core %d", hyperthread);

  #elif !LIBTEA_LINUX
  libtea_pin_to_core(GetCurrentProcess(), 0);
  DWORD_PTR processAffinityMask;
  DWORD_PTR systemAffinityMask;
  if(!GetProcessAffinityMask(GetCurrentProcess(), &processAffinityMask, &systemAffinityMask) || processAffinityMask != 1){
    libtea_info("Test 3 failed, failed to pin to core 0.");
    goto libtea_test_basic_cleanup;
  }

  #endif

  /* Success criteria: didn't crash, actually running on the core we requested */
  libtea_info("Test 3 passed.\n\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 4: physical address and system registers.");

  size_t phys_addr = libtea_get_physical_address(instance, (size_t)addr);
  libtea_info("Physical address of addr is 0x%zx", phys_addr);

  /* Try reading an MSR and writing back the same value */
  int cpu = 0;
  #if LIBTEA_LINUX
  cpu = sched_getcpu();
  #else
  cpu = GetCurrentProcessorNumber();
  #endif

  uint32_t msr = 0;
  #if LIBTEA_X86
  msr = 0xc0000080;  /* Extended Feature Enable Register (EFER), supported on both Intel and AMD */
  #elif LIBTEA_AARCH64
  msr = SYS_MAIR_EL1;
  #else
  /* PPC64 MSR functionality not implemented in driver yet */
  goto skip_msr;
  #endif

  size_t msr_val = libtea_read_system_reg(instance, cpu, msr);
  int ret = libtea_write_system_reg(instance, cpu, msr, msr_val);
  libtea_info("Read and wrote system register fine, value was 0x%zx", msr_val);

  /* Success criteria: didn't crash */
  #if LIBTEA_PPC64
  skip_msr:
  #endif
  libtea_info("Test 4 passed.\n\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 5: file handling and numeric list search.");

  char* filename;
  char* baseFilename = "test-basic.c";
  #if LIBTEA_LINUX
  filename = baseFilename;
  #else
  char filenameBuffer[MAX_PATH];
  int len = GetModuleFileNameExA(GetCurrentProcess(), NULL, filenameBuffer, MAX_PATH);
  /* Ugly hack: manually change the .exe at the end of the string to .c, because if we
   * try to map the current executable we get a sharing violation error
   */
  filenameBuffer[len-3] = 'c';
  filenameBuffer[len-2] = '\0';
  filename = filenameBuffer;
  #endif

  libtea_file fd;
  libtea_file windowsHandle;
  size_t filesize = 0;

  void* mapped_file = libtea_map_file(filename, &filesize, &fd, &windowsHandle, LIBTEA_READ);
  if(mapped_file == NULL){
    libtea_info("Test 5 failed: could not map test-basic.c (without offset)");
    goto libtea_test_basic_cleanup;
  }
  libtea_munmap_file(mapped_file, filesize, &fd, &windowsHandle);

  #if LIBTEA_LINUX
  size_t offset = 4096;
  mapped_file = libtea_map_file_by_offset(filename, &filesize, &fd, LIBTEA_READ, offset);
  if(mapped_file == NULL){
    libtea_info("Test 5 failed: could not map test-basic.c (with offset)");
    goto libtea_test_basic_cleanup;
  }
  libtea_munmap_file(mapped_file, filesize, &fd, &windowsHandle);
  #endif

  int list_int[10] = {0, 3, 8, 7, 9, 6, 1, 5, 2, 4};
  size_t list_sizet[10] = {0, 3, 8, 7, 9, 6, 1, 5, 2, 4};

  int index_int_largest = libtea_find_index_of_nth_largest_int(list_int, 10, 0);
  int index_int_smallest = libtea_find_index_of_nth_largest_int(list_int, 10, 9);
  if(list_int[index_int_largest] != 9 || list_int[index_int_smallest] != 0){
    libtea_info("Test 5 failed");
    libtea_info("Largest int number (list contains 0-9) is %d", list_int[index_int_largest]);
    libtea_info("Smallest int number (list contains 0-9) is %d", list_int[index_int_smallest]);
    goto libtea_test_basic_cleanup;
  }

  int index_sizet_largest = libtea_find_index_of_nth_largest_sizet(list_sizet, 10, 0);
  int index_sizet_smallest = libtea_find_index_of_nth_largest_sizet(list_sizet, 10, 9);
  if(list_int[index_sizet_largest] != 9 || list_int[index_sizet_smallest] != 0){
    libtea_info("Test 5 failed");
    libtea_info("Largest size_t number (list contains 0-9) is %zu", list_sizet[index_sizet_largest]);
    libtea_info("Smallest size_t number (list contains 0-9) is %zu", list_sizet[index_sizet_smallest]);
    goto libtea_test_basic_cleanup;
  }

  /* Success criteria: didn't crash, manual sanity check? */
  libtea_info("Test 5 passed.\n\n");

  // ---------------------------------------------------------------------------

  libtea_info("Starting Test 6: prefetchers");

  libtea_enable_hardware_prefetchers(instance);
  libtea_disable_hardware_prefetchers(instance);

  /* Success criteria: application didn't crash! */
  libtea_info("Test 6 passed.\n\n");

  // ---------------------------------------------------------------------------

  libtea_test_basic_cleanup:
  libtea_info("All tests complete, cleaning up...");
  free(addr);
  libtea_cleanup(instance);
  libtea_info("Done!");
  return 0;
}


#ifdef __cplusplus
}
#endif
