
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_COMMON_H
#define LIBTEA_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libtea_config.h"
#include "libtea_arch.h"

#include <fcntl.h>
#include <memory.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>


#if LIBTEA_ANDROID
#define LIBTEA_SHELL "/system/bin/sh"
#elif LIBTEA_LINUX
#define LIBTEA_SHELL "/bin/sh"
#endif

#if LIBTEA_LINUX
#include <dirent.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <sched.h>
#include <sys/fcntl.h> 
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>


#define libtea_popen(cmd, type) popen(cmd, type)
#define libtea_pclose(fd) pclose (fd)
typedef void* HANDLE;
typedef int libtea_file;
typedef int* libtea_file_ptr;
typedef pid_t libtea_thread;

#else
#include <intrin.h>
#include <malloc.h>
#include <Windows.h> //Note: this must be included before Psapi.h (despite what the SpiderMonkey linter says), otherwise compilation fails as there are missing typedefs
#include <Psapi.h>
#pragma comment(lib, "Psapi")
#define libtea_popen(cmd, type) _popen(cmd, type)
#define libtea_pclose(fd) _pclose(fd)
#define LIBTEA_WINDOWS 1    /* This is hacky but the best we can do seeing as MSVC seems to provide no Windows identifier macros */
#define NO_WINDOWS_SUPPORT libtea_info("Error: %s not supported on Windows", __func__)
typedef HANDLE libtea_file;
typedef HANDLE* libtea_file_ptr;
typedef HANDLE libtea_thread;

#if defined(_MSC_VER) || defined(__clang__)
typedef size_t pid_t;
#endif
#endif

#if defined(_MSC_VER) && (!defined(MOZJS_MAJOR_VERSION) || MOZJS_MAJOR_VERSION < 63)   /* If using Visual Studio C++ compiler. We have to explicitly exclude Firefox after MOZJS v63 as they began using clang-cl */
#define libtea_inline __forceinline
#else                                                                                  /* Assume using GCC, MinGW GCC, or Clang */
#define libtea_inline inline __attribute__((always_inline,flatten))                    /* Assume using GCC */                                    
#define LIBTEA_INLINEASM 1
#endif


#if LIBTEA_SUPPORT_CACHE
#include "libtea_cache.h"
#endif


typedef struct libtea_instance_t libtea_instance;


/**
 * Timer function
 */
typedef uint64_t (*libtea_timer_function)(libtea_instance*);


/**
 * Available high-resolution timers
 */
typedef enum {
  /** Native timer */
  LIBTEA_TIMER_NATIVE,
  /* APERF variants potentially invulnerable to DABANGG effects as they inc. at processor frequency? */
  /** AMD Zen 2+ only: APERF - higher resolution than rdtsc */
  LIBTEA_TIMER_NATIVE_AMD_ZEN2,
  /** AMD Zen only: APERF read via kernel driver (no rdpru support) */
  LIBTEA_TIMER_NATIVE_AMD_ZEN,
  /** Counting thread */
  LIBTEA_TIMER_COUNTING_THREAD,
  /** Linux perf interface */
  LIBTEA_TIMER_PERF,
  /** Monotonic clock */
  LIBTEA_TIMER_MONOTONIC_CLOCK
} libtea_timer;


typedef struct {
  unsigned char secret;
  HANDLE addr;
  int core;
} libtea_thread_data;


/* Eviction strategies are defined here rather than in libtea_cache.h as we require them for the instance definition */

/**
 * Structure containing the access strategy for eviction.
 */
typedef struct {
    int C, D, L, S;
} libtea_eviction_strategy;


/**
 * Structure containing virtual addresses of an eviction set.
 */
typedef struct {
    int addresses;
    void** address;
} libtea_eviction_set;


typedef struct {
  bool used;
  size_t n;
  void** congruent_virtual_addresses;
} libtea_congruent_address_cache_entry;


typedef struct {
  size_t mapping_size;
  void* mapping;
  libtea_file_ptr handle;
} libtea_memory;


typedef struct {
  libtea_congruent_address_cache_entry* congruent_address_cache;
  libtea_memory memory;
} libtea_eviction;


typedef struct {
    int has_pgd, has_p4d, has_pud, has_pmd, has_pt;
    int pgd_entries, p4d_entries, pud_entries, pmd_entries, pt_entries;
    int page_offset;
} libtea_paging_definition_t;


/**
 * Structure containing the local variables for a libtea instance.
 */
struct libtea_instance_t {
  #if LIBTEA_WINDOWS
  HANDLE module_fd;
  #else
  int module_fd; /* File descriptor for IOCTL access to kernel module */
  #endif
  libtea_timer_function timer;
  uint64_t measure_start;
  libtea_thread timing_thread;
  void* timing_thread_stack;
  volatile size_t thread_counter;
  libtea_thread leaky_thread;
  libtea_thread_data leaky_thread_data;
  int has_tm;
  int is_intel;
  #if LIBTEA_LINUX
  cpu_set_t cpumask;
  #endif
  int physical_cores;
  int logical_cores;
  int cpu_architecture;
  int perf_fd;
  size_t direct_physical_map;
  /** LLC Miss timing information */
  int llc_miss_threshold;
  /** LLC Hit timing information */
  int llc_hit_threshold;
  int llc_line_size;
  int llc_ways;
  int llc_sets;
  int llc_partitions;
  int llc_slices;
  int llc_size;
  int llc_set_mask;
  size_t physical_memory;
  libtea_file covert_channel_handle;
  void* covert_channel;
  libtea_eviction_strategy eviction_strategy;
  libtea_eviction_strategy prime_strategy;
  libtea_eviction* eviction;
  #if LIBTEA_SUPPORT_PAGING
  int umem_fd; /* File descriptor for read/write acess to /proc/umem */
  int mem_fd;  /* File descriptor for read/write access to /dev/mem */
  int pagesize;
  size_t paging_root;
  unsigned char* vmem;
  libtea_paging_definition_t paging_definition;
  #endif
  #if LIBTEA_LINUX
  int last_min_pstate;
  int last_max_pstate;
  int last_turbo_boost_setting;
  #endif
};


/* These need to be static so that each .c file including the header has its own copy */
#if LIBTEA_LINUX
static sigjmp_buf libtea__trycatch_buf;
#else
static jmp_buf libtea__trycatch_buf;
#endif
typedef void (*sighnd_t)(int);
static sighnd_t libtea__saved_sighandler[32];
static libtea_instance* libtea__instances[32];
void libtea__trycatch_segfault_handler(int signum);
static void libtea__try_start_prep();


/* Return values for "void" functions which can fail.
 * Functions which normally return a variable will return NULL on error. */
#define LIBTEA_SUCCESS 0
#define LIBTEA_ERROR -1

#define LIBTEA_READ 0
#define LIBTEA_WRITE 1
#define LIBTEA_READ_WRITE 2


/**
 * Initializes a libtea instance and initializes and acquires kernel module.
 *
 * :return: Returns a libtea instance
 */
libtea_instance* libtea_init();


/**
 * Initializes a libtea instance without the kernel module (paging, interrupts, and enclave functionality will be disabled).
 *
 * :return: Returns a libtea instance
 */
libtea_instance* libtea_init_nokernel();


/**
 * Cleans up the libtea instance and (if necessary) releases the kernel module.
 */
void libtea_cleanup(libtea_instance* instance);


/**
 * Accesses the provided address.
 *
 * :param addr: Virtual address
 */
#define libtea_access(addr) libtea__arch_access(addr)


/**
 * Accesses the provided address (with memory barriers).
 *
 * :param addr: Virtual address
 */
#define libtea_access_b(addr) libtea__arch_access_b(addr)


/**
 * Accesses the provided address speculatively. Success will vary depending on the microarchitecture
 * used (exact branch prediction implementation, ROB size etc).
 *
 * :param addr: Virtual address
 */
libtea_inline void libtea_access_speculative(void* addr);


/**
 * Prefetches the provided address.
 *
 * :param addr: Virtual address
 */
#define libtea_prefetch(addr) libtea__arch_prefetch(addr)


/**
 * Prefetches the provided address in anticipation of a write to the address.
 *
 * :param addr: Virtual address
 */
#define libtea_prefetch_anticipate_write(addr)  libtea__arch_prefetchw(addr)


/**
 * Flushes the provided address from the cache.
 *
 * :param addr: Virtual address
 */
#define libtea_flush(addr) libtea__arch_flush(addr)


/**
 * Flushes the provided address from the cache (with memory barriers).
 *
 * :param addr: Virtual address.
 */
#define libtea_flush_b(addr) libtea__arch_flush_b(addr)


/**
 * Begin memory barrier.
 */
#define libtea_barrier_start() libtea__arch_barrier_start()


/**
 * End memory barrier.
 *
 * Note: unnecessary on x86.
 *
 */
#define libtea_barrier_end() libtea__arch_barrier_end()


/**
 * Insert a speculation barrier.
 *
 */
#define libtea_speculation_barrier() libtea__arch_speculation_barrier()


/**
 * Returns the current timestamp.
 *
 * :param instance: The libtea instance
 * :return: The current timestamp
 */
libtea_inline uint64_t libtea_timestamp(libtea_instance* instance);


/**
 * Begins a timing measurement.
 *
 * :param instance: The libtea instance
 */
libtea_inline void libtea_measure_start(libtea_instance* instance);


/**
 * Ends a timing measurement and returns the elapsed time.
 *
 * :param instance: The libtea instance
 * :return: Elapsed time since the start of the measurement
 */
libtea_inline uint64_t libtea_measure_end(libtea_instance* instance);


/**
 * Configures which timer is used.
 *
 * Note: on most systems you will need to run as root to use LIBTEA_PERF_TIMER.
 * Otherwise it will fail silently (returning 0).
 *
 * :param instance: The libtea instance
 * :param timer: The timer to use
 */
libtea_inline static void libtea_set_timer(libtea_instance* instance, libtea_timer timer);


/**
 * Begins a try/catch block using signal handling.
 *
 * Usage: libtea_try_start() { ... }
 */
#if LIBTEA_LINUX
#define libtea_try_start()  libtea__try_start_prep(); if(!sigsetjmp(libtea__trycatch_buf, 1))
#else
#define libtea_try_start()  libtea__try_start_prep(); if(!setjmp(libtea__trycatch_buf))
#endif


/**
 * Ends the signal handling try/catch block and restores the
 * previous signal handlers.
 */
#define libtea_try_end()                                                                \
  do{                                                                                     \
    signal(SIGILL, libtea__saved_sighandler[0]);                                        \
    signal(SIGFPE, libtea__saved_sighandler[1]);                                        \
    signal(SIGSEGV, libtea__saved_sighandler[2]);                                       \
  } while(0)


/**
 * Aborts the signal handling try/catch block by triggering a segmentation fault.
 *
 * Note: this function assumes that NULL (the zero page) is not mapped into the process' memory.
 */
#define libtea_try_abort()  libtea_access(0)


/**
 * Aborts the signal handling try/catch block via a siglongjmp.
 */
#define libtea_try_abort_noexcept()  siglongjmp(libtea__trycatch_buf, 1)


/**
 * Begins a try/catch block using using transactional memory.
 *
 * Note: this function will throw an exception if you try to execute it without
 * a supported transactional memory implementation (Intel TSX or PowerPC HTM).
 *
 * Usage: libtea_try_start_tm() { ... }
 */
#define libtea_try_start_tm()  if(libtea__arch_transaction_begin())


/**
 * Ends the transactional try/catch block.
 *
 * Note: Intel TSX will segfault if this is used outside of a transaction
 * (i.e. a libtea_try_start_tm() block).
 */
#define libtea_try_end_tm() libtea__arch_transaction_end()


/**
 * Aborts the transactional try/catch block.
 */
#define libtea_try_abort_tm()  libtea__arch_transaction_abort()


#if LIBTEA_INLINEASM

/**
 * Starts a specpoline block (code within will only be executed transiently).
 *
 * :param label: A goto label to use in the inline assembly.
 *
 * Note: you must pass the same label to the corresponding libtea_speculation_end,
 * and you must use a different label each time you call libtea_speculation_start
 * within the same program, or it will fail to compile ("redefinition of label").
 */
#define libtea_speculation_start(label)  libtea__arch_speculation_start(label)

/**
 * Ends a specpoline block.
 *
 * :param label: A goto label to use in the inline assembly. (See notes for libtea_speculation_start.)
 */
#define libtea_speculation_end(label)  libtea__arch_speculation_end(label)

#endif


/**
 * Gets the sibling hyperthread of the provided core (Linux-only).
 *
 * :param logical_core: The logical core
 * :return: The id of the sibling hyperthread or LIBTEA_ERROR
 */
libtea_inline int libtea_get_hyperthread(int logical_core);


/**
 * Pins a process to the provided core.
 *
 * :param process: The process to pin
 * :param core: The core the process should be pinned to
 */
libtea_inline void libtea_pin_to_core(libtea_thread process, int core);


/**
 * Returns the physical address of the provided virtual address.
 *
 * Note: this function must be run with root privileges.
 *
 * :param instance: The libtea instance
 * :param addr: The virtual address
 * :return: The corresponding physical address or LIBTEA_ERROR
 */
libtea_inline size_t libtea_get_physical_address(libtea_instance* instance, size_t addr);


/**
 * Opens a shared memory region.
 *
 * Note: libtea only supports one shared memory region being open at
 * a time. You must close the shared memory when you finish using it using
 * libtea_close_shared_memory().
 *
 * :param size: Desired size of the region in bytes
 * :param windowsMapping: Returns the Windows mapping handle (ignored on Linux)
 *
 * :return: A void* or Handle pointer to the shared memory, or NULL if
 * an error occurred.
 */
libtea_inline HANDLE libtea_open_shared_memory(size_t size, libtea_file_ptr windowsMapping);


/**
 * Closes a shared memory region created with open_shared_memory.
 *
 * Note: libtea only supports one shared memory region being open at
 * a time.
 *
 * :param mem: Pointer or Handle to the shared memory region
 * :param windowsMapping: The Windows mapping handle (ignored on Linux)
 * :param size: Size of the region in bytes
 *
 * :return: LIBTEA_SUCCESS on success, LIBTEA_ERROR otherwise
 */
libtea_inline int libtea_close_shared_memory(HANDLE mem, libtea_file_ptr windowsMapping, size_t size);


/**
 * Starts a leaky thread.
 *
 * :param instance: The libtea instance.
 * :param type: The type of leaky thread to create. 1 for load loop, 2 for store loop, 3 for nop loop.
 * :param secret: A byte value to repeatedly load/store (ignored for nop loop, but you must still provide a value).
 * :param shared: A void pointer / HANDLE to a shared memory region, or NULL to not use shared memory.
 * :param core: The CPU core to lock the thread to.
 *
 * :return: A libtea_thread handle, or 0 (Linux) / NULL (Windows) if an error occurred.
 */
libtea_thread libtea_start_leaky_thread(libtea_instance* instance, int type, unsigned char secret, HANDLE shared, int core);


/**
 * Stops the victim thread initialized with libtea_start_leaky_thread().
 *
 * :param instance: The libtea instance.
 */
void libtea_stop_leaky_thread(libtea_instance* instance);


/**
 * Maps a page of the given file at the defined offset to the program's
 * address space and returns its address (Linux-only).
 *
 * Note: This function leaks memory.
 *
 * :param filename: The path to the file
 * :param filesize: Returns the size of the file (if not NULL)
 * :param fileHandle: Returns the file descriptor / handle
 * :param rw: LIBTEA_READ for a read-only mapping, LIBTEA_WRITE for write-only (Linux-only), LIBTEA_READ_WRITE for read-write
 * :param offset: The offset that should be mounted
 *
 * :return: Mapped address or NULL if any error occurs
 */
libtea_inline void* libtea_map_file_by_offset(const char* filename, size_t* filesize, libtea_file_ptr fileHandle, int rw, size_t offset);


/**
 * Maps an entire file and returns its address.
 *
 * Note: This function leaks memory. On Windows, you must also close the
 * underlying file (fileHandle) in addition to unmapping the file.
 *
 * :param filename: The path to the file
 * :param filesize: Returns the size of the file (if not NULL)
 * :param fileHandle: Returns the file descriptor / handle
 * :param windowsMapping: Returns the Windows mapping handle (ignored on Linux)
 * :param rw: LIBTEA_READ for a read-only mapping, LIBTEA_WRITE for write-only (Linux-only), LIBTEA_READ_WRITE for read-write
 * :return: Mapped address or NULL if any error occurs
 */
libtea_inline void* libtea_map_file(const char* filename, size_t* filesize, libtea_file_ptr fileHandle, libtea_file_ptr windowsMapping, int rw);


/**
 * Maps a region of memory (not backed by an underlying file).
 * This function exists to facilitate Linux/Windows cross-compatibility.
 *
 * Note: This function leaks memory. You should unmap the allocated
 * region with libtea_munmap().
 *
 * :param buffer_size: The size of the region to map
 * :param handle: Returns the Windows mapping handle (ignored on Linux)
 * :param rw: LIBTEA_READ for a read-only mapping, LIBTEA_WRITE for write-only (Linux-only), LIBTEA_READ_WRITE for read-write
 * :return: Pointer to the mapper region (or NULL on error)
 */
libtea_inline void* libtea_mmap(int buffer_size, libtea_file_ptr windowsMapping, int rw);


/**
 * Unmaps a memory-mapped file. This function exists to facilitate
 * Linux/Windows cross-compatibility.
 *
 * :param ptr: Pointer to the region to unmap
 * :param buffer_size: The size of the region (ignored on Windows)
 * :param fileHandle: File descriptor / handle
 * :param windowsMapping: The Windows mapping handle (ignored on Linux)
 * :return: LIBTEA_SUCCESS on success, LIBTEA_ERROR otherwise
 */
libtea_inline int libtea_munmap_file(void* ptr, int buffer_size, libtea_file_ptr fileHandle, libtea_file_ptr windowsMapping);


/**
 * Unmaps a (non file-backed) mapped region of memory. This function
 * exists to facilitate Linux/Windows cross-compatibility.
 *
 * :param ptr: Pointer to the region to unmap
 * :param buffer_size: The size of the region (ignored on Windows)
 * :param windowsMapping: The Windows mapping handle (ignored on Linux)
 * :return: LIBTEA_SUCCESS on success, LIBTEA_ERROR otherwise
 */
libtea_inline int libtea_munmap(void* ptr, int buffer_size, libtea_file_ptr windowsMapping);


/**
 * Finds the index of the nth largest integer in the list.
 *
 * :param list: The list
 * :param nmemb: Number of list entries
 * :param n: Value of n (0 == largest)
 * :return: The index
 */
libtea_inline int libtea_find_index_of_nth_largest_int(int* list, size_t nmemb, size_t n);


/**
 * Finds the index of the nth largest size_t in the list.
 *
 * :param list: The list
 * :param nmemb: Number of list entries
 * :param n: Value of n (0 == largest)
 * :return: The index
 */
libtea_inline int libtea_find_index_of_nth_largest_sizet(size_t* list, size_t nmemb, size_t n);


/**
 * Writes to a model-specific register (MSR) / system register.
 *
 * Note: requires the msr driver (x86 only) or the libtea driver.
 *
 * :param instance: The libtea instance
 * :param cpu: The core ID
 * :param reg: The register
 * :param val: The value
 * :return: LIBTEA_SUCCESS or LIBTEA_ERROR
 */
libtea_inline int libtea_write_system_reg(libtea_instance* instance, int cpu, uint32_t reg, uint64_t val);


/**
 * Reads from a model-specific register (MSR) / system register.
 *
 * Note: requires the msr driver (x86 only) or the libtea driver.
 *
 * :param instance: The libtea instance
 * :param cpu: The core ID
 * :param reg: The register
 * :return: The value of the register or LIBTEA_ERROR
 */
libtea_inline size_t libtea_read_system_reg(libtea_instance* instance, int cpu, uint32_t reg);


/**
 * Disables all hardware prefetchers (supported on Intel only).
 *
 * :param instance: The libtea instance
 */
libtea_inline void libtea_disable_hardware_prefetchers(libtea_instance* instance);


/**
 * Enables all hardware prefetchers (supported on Intel only).
 *
 * :param instance: The libtea instance
 */
libtea_inline void libtea_enable_hardware_prefetchers(libtea_instance* instance);


/**
 * Attempts to isolate the provided CPU core by removing it from the affinity mask of all
 * running user processes. It is unfortunately not possible to modify the affinity of
 * system processes.
 *
 * Note: only supported on Windows; must be run with administrator privileges. On Linux,
 * boot with the isolcpus=X parameter set or (preferred) use the cset-shield tool.
 *
 * This is an experimental function and is only enabled if LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION
 * is set to 1 in libtea_config.h.
 *
 * :param core: The CPU core to isolate
 * :return: LIBTEA_SUCCESS on success, otherwise LIBTEA_ERROR
 */
#if LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION
libtea_inline int libtea_isolate_windows_core(int core);
#endif


/**
 * Attempts to lock the CPU to a stable P-state for reproducible microarchitectural attack or
 * benchmark results. Disables Turbo Boost and sets both the minimum and maximum P-state to the
 * provided value (provided as a percentage of available performance).
 *
 * Note: only supported for Intel CPUs on Linux (depends on the intel_pstate module).
 *
 * :param instance: The libtea instance
 * :param perf_percentage: The integer percentage of available performance to lock to
 * :return: LIBTEA_SUCCESS on success, otherwise LIBTEA_ERROR
 */
libtea_inline int libtea_set_cpu_pstate(libtea_instance* instance, int perf_percentage);


/*
 * Restores the CPU P-state and Turbo Boost settings to their state prior to the last call of
 * libtea_set_cpu_pstate. Do not use without first calling libtea_set_cpu_pstate.
 *
 * Note: only supported for Intel CPUs on Linux (depends on the intel_pstate module).
 *
 * :param instance: The libtea instance
 * :return: LIBTEA_SUCCESS on success, otherwise LIBTEA_ERROR
 */
libtea_inline int libtea_restore_cpu_pstate(libtea_instance* instance);


#if LIBTEA_SILENT
#define libtea_info(msg, ...)
#else
#define libtea_info(msg, ...)                                         \
  do {                                                                  \
    printf("[" __FILE__ "] " msg "\n", ##__VA_ARGS__);      \
    fflush(stdout);                                                     \
  } while(0)

#endif

#define libtea_always_print_info(msg, ...)                            \
  do {                                                                  \
    printf("[" __FILE__ "] " msg "\n", ##__VA_ARGS__);      \
    fflush(stdout);                                                     \
  } while(0)


/* Use a hard assert for select Interrupt/Enclave functionality
 * where continuing execution in an invalid state could lead to
 * a system hang / unpredictable behavior.
 */
#define libtea_assert(cond)                                  \
    do {                                                     \
        if (!(cond))                                         \
        {                                                    \
            printf("Assertion '" #cond "' failed.");         \
            exit(EXIT_FAILURE);                              \
        }                                                    \
    } while(0);


#if !defined(_GNU_SOURCE) && LIBTEA_LINUX
int clone(int (*fn)(void *), void *child_stack,
                 int flags, void *arg, ...
                 /* pid_t *ptid, void *newtls, pid_t *ctid */ );
int sched_setaffinity(pid_t pid, size_t cpusetsize,
                             const cpu_set_t *mask);

int sched_getaffinity(pid_t pid, size_t cpusetsize,
                             cpu_set_t *mask);
int sched_getcpu(void);
#endif


#ifdef __cplusplus
}
#endif


#endif //LIBTEA_COMMON_H
