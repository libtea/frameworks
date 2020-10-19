# libtea
libtea is a framework for rapid prototyping of microarchitectural attacks on Linux, compatible with x86 (32-bit and 64-bit, Intel and AMD CPUs) and AArch64. It consists of a kernel module and a configurable C header and offers the following features:
* Attack primitives for cache attacks and transient execution attacks
* User mode modification of page tables and model-specific/system registers
* **x86 only:** user mode configuration of APIC timer interrupts and registration of custom interrupt handlers (for both user mode and kernel mode), enabling single- and zero-stepping of execution (particularly useful against SGX enclaves) and arbitrary ring 0 (kernel mode) code execution

It should be immediately apparent from the feature list above that libtea should **not under any circumstances** be used on a system where security or uptime is critical. Be aware that careless usage of libtea's features may crash your system. You should unload the libtea kernel module as soon as you are finished using it.

Note: libtea has been designed to be as portable as possible, but to date has only been tested on Ubuntu 19.10, Ubuntu 20.04, and Windows 10. 


## Linux Build Instructions
Run the make recipe for the modules you would like included in the libtea library header.
* The recipes are of the form `libtea-arch-features`.
* Available values for arch are: `x86`, `aarch64`, and `ppc64`.
* Available values for features are: `basic`, `cache`, `paging` (x86 and aarch64 only), `interrupts` (x86 only), `enclave` (Intel x86 only).
* For `enclave` functionality, run `git submodule init` and `git submodule update` before building (to also download the Intel SGX SDK and driver).

These recipes build the Libtea header and kernel module with the selected feature configuration, and also build the relevant tests for this configuration. The tests demonstrate example usage of the API and can be found in the `tests` folder.

Once you have built the header, simply copy it into your project and include it:
``` C
#include "libtea.h"
```

If you use libtea with the `interrupts` or `enclave` modules enabled you will additionally need to alter your project's Makefile to include the ASM files - see the libtea-x86-interrupts and libtea-x86-enclave Makefile recipes for details.

To use any of libtea's kernel-mode functionality you will need to load the kernel module: 

``` bash
cd module
sudo insmod libtea.ko
```

On x86, it is recommended to also load the msr module, and if using enclave functionality you will need the SGX driver (isgx) loaded. 

To unload the kernel module:
``` bash
sudo rmmod libtea
```

## Windows Build Instructions
On Windows, libtea is designed to be built from Visual Studio Code. The file `.vscode\tasks.json` contains all required Visual Studio Code build tasks. You will also need to install the Visual Studio C/C++ Build Tools, the Windows SDK, and the Windows Driver Kit (WDK). 

Note: Compiling with MinGW GCC is also supported and included as a Visual Studio Code build task.

### Building the Library
**Note: Visual Studio Code must be run from the x64 Native Tools Command Prompt for VS 2019 (or your respective Visual Studio Build Tools version) in order to configure the environment variables correctly. If you do not do this, the ASM and cl.exe build tasks may fail.**

Go to Terminal > Run Task in Visual Studio Code and run the tasks in the following order:
* Configure library header with Powershell script
* Build object file for Windows ASM
* Compile library with cl.exe
The tasks contain the full commands in JSON format if you wish to instead run these from the command line. The Powershell script will prompt you to enter a build value to configure which features will be included. Available values are `basic`, `cache` (includes basic functionality), and `paging` (includes cache and basic functionality).

### Disabling Driver Signature Enforcement
To temporarily disable driver signature enforcement, hold the Shift key while clicking on Restart in the start menu. This will restart your computer into an options menu where you can disable driver signature enforcement by going to Troubleshoot > Advanced Options > Startup Settings and pressing 7 or F7. Once the PC has started, the driver can be loaded (but only until the next restart).

Alternatively, to permanently disable driver signature enforcement, enable Windows test mode by entering the following in a command prompt with Administrator privileges:

```
bcdedit /set testsigning on
```

To disable test mode, run

```
bcdedit /set testsigning off
```

### Building and Loading the Driver
Run the 'Compile libtea driver with MSBuild' and 'Compile libtea driver loader with MSBuild' tasks from Visual Studio Code. If you have errors reporting missing libraries, ensure that you have the Windows Driver Development Kit (DDK) installed, along with the MSVC C++ x64/x86, C++ ATL (x86 & x64), and C++ MFC (x86 & x64) libraries (with their versions matching your Visual Studio Build Tools version). The libraries can be installed from the Visual Studio Installer, which will be present on your system if you have the Build Tools installed (click 'modify' to select additional components).

The compiled drivers will be available at `driver\Libtea\x64\Debug\Libtea.sys` and `driver\LibteaLoader\x64\Debug\LibteaLoader.exe`. Copy both files into the top-level `driver` folder.

To load the driver, simply run the following from a command prompt with Administrator privileges:

```
LibteaLoader.exe
```

You can check the driver has loaded correctly by running the `driverquery` command and checking that 'Libtea' is listed.

To unload the driver, run:
```
LibteaLoader.exe --unload
```


### Environment Variables
libtea supports a variety of configuration variables if you would like to override the auto-calibrated settings.
Sometimes this is necessary, e.g. if libtea cannot detect all characteristics of your CPU caches (currently the case on Android devices).
You can export values for the following:
* `LIBTEA_LLC_SLICES`
* `LIBTEA_LLC_LINE_SIZE`
* `LIBTEA_LLC_SETS`
* `LIBTEA_LLC_PARTITIONS`
* `LIBTEA_HIT_THRESHOLD`
* `LIBTEA_MISS_THRESHOLD`
* `LIBTEA_EVICTION_STRATEGY` (expressed as C-D-L-S)
* `LIBTEA_PRIME_STRATEGY` (expressed as C-D-L-S)
* `LIBTEA_DUMP` (to print the configuration at initialization time)

Many libtea functions require a binary to be running with root privileges.
If you are using sudo rather than a root shell to run your binary, use the -E option (change bash to your shell) to preserve your environment variables:
```
sudo -E bash -c ./my-libtea-program
```

### API

Common Functionality            | Description
--------------------------------|---------------------------------------------
`libtea_instance* libtea_init()`  | Initializes and returns a libtea instance; initializes and acquires kernel module.
`libtea_instance* libtea_init_nokernel()` | Initializes and returns a libtea instance without the kernel module (paging, interrupts, and enclave functionality will be disabled).
`void libtea_cleanup(libtea_instance* instance)` | Cleans up the libtea instance and (if necessary) releases the kernel module.
`void libtea_access(void* addr)` | Accesses the provided address.
`void libtea_acccess_b(void* addr)` | Accesses the provided address (with memory barriers).
`void libtea_access_speculative(void* addr)` | Accesses the provided address speculatively. Success will vary depending on the microarchitecture used (exact branch prediction implementation, ROB size etc).
`void libtea_prefetch(void* addr)` | Prefetches the provided address.
`void libtea_prefetch_anticipate_write(void* addr)` | Prefetches the provided address in anticipation of a write to the address.
`void libtea_flush(void* addr)` | Flushes the provided address from the cache.
`void libtea_flush_b(void* addr)` | Flushes the provided address from the cache (with memory barriers).
`void libtea_barrier_start()` | Begin memory barrier.
`void libtea_barrier_end()` | End memory barrier. Note: unnecessary on x86.
`void libtea_speculation_barrier()` | Insert a speculation barrier.
`uint64_t libtea_timestamp(libtea_instance* instance)` | Returns the current timestamp.
`void libtea_measure_start(libtea_instance* instance)` | Begins a timing measurement.
`uint64_t libtea_measure_end(libtea_instance* instance)` | Ends a timing measurement and returns the elapsed time.
`void libtea_set_timer(libtea_instance* instance, libtea_timer timer)` |  Configures which timer is used. Choose from `LIBTEA_TIMER_NATIVE`, `LIBTEA_TIMER_NATIVE_AMD_ZEN2`, `LIBTEA_TIMER_NATIVE_AMD_ZEN`, `LIBTEA_TIMER_COUNTING_THREAD`, `LIBTEA_TIMER_PERF`, and `LIBTEA_TIMER_MONOTONIC_CLOCK`. Note: on most systems you will need to run as root to use `LIBTEA_PERF_TIMER`. Otherwise it will fail silently (returning 0).
`void libtea_try_start()` | Begins a try/catch block using signal handling. Use like an if block: `libtea_try_start() { ... }`.
`void libtea_try_end()` | Ends the signal handling try/catch block and restores the previous signal handlers.
`noreturn libtea_try_abort()` | Aborts the signal handling try/catch block by triggering a segmentation fault.
`noreturn libtea_try_abort_noexcept()` | Aborts the signal handling try/catch block via a siglongjmp.
`void libtea_try_start_tm()` | Begins a try/catch block using using transactional memory. Note: this function will throw an exception if you try to execute it without a supported transactional memory implementation (Intel TSX or PowerPC HTM). Use like an if block: `libtea_try_start_tm() { ... }`.
`void libtea_try_end_tm()` | Ends the transactional try/catch block. Note: Intel TSX will segfault if this is used outside of a transaction (i.e. a `libtea_try_start_tm()` block).
`noreturn libtea_try_abort_tm()` | Aborts the transactional try/catch block.
`void libtea_speculation_start(label)` | Starts a specpoline block (code within will only be executed transiently). Provide: a goto label to use in the inline assembly. Note: you must pass the same label to the corresponding `libtea_speculation_end()` call, and you must use a different label each time you call `libtea_speculation_start()` within the same program, or it will fail to compile ("redefinition of label").
`void libtea_speculation_end(label)` | Ends a specpoline block. Provide: a goto label to use in the inline assembly. See notes for `libtea_speculation_start()`.
`int libtea_get_hyperthread(core)` | Returns the sibling hyperthread of the provided core (Linux-only) or `LIBTEA_ERROR`.
`void libtea_pin_to_core(libtea_thread process, int core)` | Pins a process to the provided core.
`size_t libtea_get_physical_address(libtea_instance* instance, size_t addr)` | Returns the physical address of the provided virtual address or `LIBTEA_ERROR`. Note: this function must be run with root privileges.
`HANDLE libtea_open_shared_memory(size_t size, libtea_file_ptr windowsMapping)` | Opens a shared memory region and returns a HANDLE to it. Note: libtea only supports one shared memory region being open at a time. You must close the shared memory when you finish using it using `libtea_close_shared_memory()`. Provide: desired size of the region in bytes; a pointer to a variable to store the Windows mapping handle (ignored on Linux).
`int libtea_close_shared_memory(HANDLE mem, libtea_file_ptr windowsMapping, size_t size)` | Closes a shared memory region created with open_shared_memory. Note: libtea only supports one shared memory region being open at a time. Provide: a HANDLE to the shared memory region; a pointer to the Windows mapping handle (ignored on Linux); size of the region in bytes. Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`.
`libtea_thread libtea_start_leaky_thread(libtea_instance* instance, int type, unsigned char secret, HANDLE shared, int core)` | Starts a leaky thread and returns a `libtea_thread` handle, or 0 (Linux) / NULL (Windows) if an error occurred. Provide: the libtea instance; the type of leaky thread to create (1 for load loop, 2 for store loop, 3 for nop loop); a byte value to repeatedly load/store (ignored for nop loop, but you must still provide a value); a HANDLE to a shared memory region, or NULL to not use shared memory; the CPU core to lock the thread to.
`void libtea_stop_leaky_thread(libtea_instance* instance)` | Stops the victim thread initialized with `libtea_start_leaky_thread()`.
`void* libtea_map_file_by_offset(const char* filename, size_t* filesize, libtea_file_ptr fileHandle, int rw, size_t offset)` | Maps a page of the given file at the defined offset to the program's address space and returns its address or NULL if an error occurs (Linux-only). Note: This function leaks memory. Provide: the path to the file; pointer to store the size of the file; pointer to store the file descriptor / handle; `LIBTEA_READ` for a read-only mapping, `LIBTEA_WRITE` for write-only (Linux-only), or `LIBTEA_READ_WRITE` for read-write; the offset.
`void* libtea_map_file(const char* filename, size_t* filesize, libtea_file_ptr fileHandle, libtea_file_ptr windowsMapping, int rw)` | Maps an entire file and returns its address or NULL if an error occurs. Note: This function leaks memory. On Windows, you must also close the underlying file (fileHandle) in addition to unmapping the file. Provide: the path to the file; pointer to store the size of the file; pointer to store the file descriptor / handle; pointer to store the Windows mapping handle (ignored on Linux); `LIBTEA_READ` for a read-only mapping, `LIBTEA_WRITE` for write-only (Linux-only), or `LIBTEA_READ_WRITE` for read-write.
`void* libtea_mmap(int buffer_size, libtea_file_ptr windowsMapping, int rw)` | Maps a region of memory (not backed by an underlying file) and returns its address or NULL if an error occurs. This function exists to facilitate Linux/Windows cross-compatibility. Note: This function leaks memory. You should unmap the allocated region with `libtea_munmap()`. Provide: the size of the region to map; pointer to store the Windows mapping handle (ignored on Linux); `LIBTEA_READ` for a read-only mapping, `LIBTEA_WRITE` for write-only (Linux-only), or `LIBTEA_READ_WRITE` for read-write.
`int libtea_munmap_file(void* ptr, int buffer_size, libtea_file_ptr fileHandle, libtea_file_ptr windowsMapping)` | Unmaps a memory-mapped file and returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`. This function exists to facilitate Linux/Windows cross-compatibility. Provide: pointer to the region to unmap; the size of the region (ignored on Windows); the file descriptor/handle; the Windows mapping handle (ignored on Linux).
`int libtea_munmap(void* ptr, int buffer_size, libtea_file_ptr windowsMapping)` | Unmaps a (non file-backed) mapped region of memory and returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`. This function exists to facilitate Linux/Windows cross-compatibility. Provide: pointer to the region to unmap; the size of the region (ignored on Windows); the Windows mapping handle (ignored on Linux).
`int libtea_find_index_of_nth_largest_int(int* list, size_t nmemb, size_t n)` | Returns the index of the nth largest int in the list. Provide: the list; the number of list entries; value of n (0 == largest).
`int libtea_find_index_of_nth_largest_sizet(size_t* list, size_t nmemb, size_t n)` | Returns the index of the nth largest size_t in the list. Provide: the list; the number of list entries; value of n (0 == largest).
`int libtea_write_system_reg(libtea_instance* instance, int cpu, uint32_t reg, uint64_t val)` | Writes to a model-specific register (MSR) / system register and returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`. Note: requires the `msr` driver (x86 only) or the libtea driver. Provide: the libtea instance; the CPU core ID; the register; the value to write.
`size_t libtea_read_system_reg(libtea_instance* instance, int cpu, uint32_t reg)` | Reads from a model-specific register (MSR) / system register and returns its value or `LIBTEA_ERROR`. Note: requires the `msr` driver (x86 only) or the libtea driver. Provide: the libtea instance; the CPU core ID; the register.
`void disable_hardware_prefetchers(libtea_instance* instance)` | Disables all hardware prefetchers (supported on Intel only).
`void libtea_enable_hardware_prefetchers(libtea_instance* instance)` | Enables all hardware prefetchers (supported on Intel only).
`int libtea_set_cpu_pstate(libtea_instance* instance, int perf_percentage)` | Disables Turbo Boost and sets the CPU minimum and maximum P-states to the provided integer percentage of available performance to improve reproducibility of attack and benchmark results. Supported for Intel CPUs on Linux only. Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR` if the values could not be written.
`int libtea_restore_cpu_pstate(libtea_instance* instance) ` | Restores the CPU minimum and maximum P-states and Turbo Boost setting to their original values prior to the last call to libtea_set_cpu_pstate. Supported for Intel CPUs on Linux only. Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR` if the values could not be restored.

Cache Functionality            | Description
--------------------------------|---------------------------------------------
`int libtea_flush_reload(libtea_instance* instance, void* addr)` | Performs Flush+Reload on the provided address and returns hit/miss (1 if cached, 0 if not) based on the current threshold.
`void libtea_calibrate_flush_reload(libtea_instance* instance)` | Calibrates the threshold to distinguish between a cache hit and cache miss using Flush+Reload.
`int libtea_get_cache_slice(libtea_instance* instance, size_t paddr)` | Returns the cache slice of the provided physical address. Note: only supported on Intel.
`int libtea_get_cache_set(libtea_instance* instance, size_t paddr)` | Returns the cache set of the provided physical address.
`int libtea_build_eviction_set(libtea_instance* instance, libtea_eviction_set* set, size_t paddr)` | Builds an eviction set for the provided physical address and returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`.
`void libtea_evict(libtea_instance* instance, libtea_eviction_set set)` | Runs eviction using the provided eviction set.
`int libtea_evict_reload(libtea_instance* instance, void* addr, libtea_eviction_set set)` | Performs Evict+Reload using the provided eviction set and returns 1 if the address was cached (based on the current threshold).
`void libtea_calibrate_evict_reload(libtea_instance* instance)` | Calibrates the threshold to distinguish between a cache hit and cache miss using Evict+Reload.
`void libtea_prime(libtea_instance* instance, libtea_eviction_set set)` | Performs the prime step using the provided eviction set.
`int libtea_prime_probe(libtea_instance* instance, libtea_eviction_set set)` | Performs Prime+Probe and builds an eviction set for the provided address if one does not exist. Returns the execution time of the probe step.
`size_t libtea_measure_slice(libtea_instance* instance, void* address)` | Returns the slice ID of the virtual address by measuring with performance counters (requires MSR access). Note: only supported on Intel.
`void libtea_cache_encode(libtea_instance* instance, unsigned char value)` | Encodes the provided value into the cache.
`void libtea_cache_encode_dereference(libtea_instance* instance, char* ptr, int offset)` | Dereferences a pointer at the provided offset and encodes the dereferenced value into the cache. This function is intended for use with SCFirefox.
`void libtea_fast_cache_encode(libtea_instance* instance, void* addr)` | Similar to libtea_cache_encode_dereference, but uses optimized assembly to encode within an extremely short transient window. Currently supported on x86 only.
`int libtea_cache_decode_from_to(libtea_instance* instance, int from, int to, bool use_mix)` | Decodes a value in a given range from the cache. Returns the decoded value or `LIBTEA_ERROR`. Note: you must ensure that the 'from' and 'to' values you specify do not exceed the value of instance->covert_channel_entries (255 by default). Provide: the libtea instance; the index in the covert channel to start decoding from (inclusive); the index in the covert channel to stop decoding at (inclusive); a boolean representing whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
`int libtea_cache_decode(libtea_instance* instance, bool use_mix)` | Decodes a value encoded into the cache covert channel. Returns the decoded value or `LIBTEA_ERROR`. Provide: the libtea instance; a boolean representing whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without `use_mix` first.
`int libtea_cache_decode_nonull(libtea_instance* instance, bool use_mix)` | Decodes a value encoded into the cache covert channel (ignoring null/0). Returns the decoded value or `LIBTEA_ERROR`. Provide: the libtea instance; a boolean representing whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: can destroy the signal on some CPUs; always try without use_mix first.
`void libtea_cache_decode_histogram_iteration(libtea_instance* instance, bool use_mix, bool print, int offset, int from, int to, int* hist)` | Decodes a value encoded into the cache covert channel and updates a histogram. Provide: the libtea instance; a boolean representing whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects; whether to output the updated histogram to stdout; the offset to add to the covert channel index to print the actual encoded character (if using <256 entries); the index in the covert channel to start decoding from (inclusive);the index in the covert channel to stop decoding at (inclusive); the histogram to modify (expects an int array with 256 elements).
`void libtea_print_cache_decode_histogram(libtea_instance* instance, int iterations, int sleep_len, bool yield, bool use_mix, void(*activity)(), int offset, int from, int to)` | Prints a histogram of decoded cache covert channel values to stdout for the provided number of iterations. Note: this function repeatedly clears the terminal window. Provide: the libtea instance; the number of iterations to repeat for; the number of microseconds to sleep for between iterations (0 to not sleep); whether to call `sched_yield()` / `SwitchToThread()` between iterations; whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects; a pointer to a function which should be called before each decode, e.g. a call to the victim (can be NULL to do nothing); the offset to add to the covert channel index to get the actual encoded character (if using <256 entries); the index in the covert channel to start decoding from (inclusive); the index in the covert channel to stop decoding at (inclusive).
`int* libtea_numeric_cache_decode_histogram(libtea_instance* instance, int iterations, int sleep_len, bool yield, bool use_mix, void(*activity)(), int offset, int from, int to)` | Returns a histogram of decoded cache covert channel values over the provided number of iterations as an int array. Provide: the libtea instance; the number of iterations to repeat for; the number of microseconds to sleep for between iterations (0 to not sleep); whether to call `sched_yield()` / `SwitchToThread()` between iterations; whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects; a pointer to a function which should be called before each decode, e.g. a call to the victim (can be NULL to do nothing); the offset to add to the covert channel index to get the actual encoded character (if using <256 entries); the index in the covert channel to start decoding from (inclusive); the index in the covert channel to stop decoding at (inclusive).
`int libtea_check_decoded(char* decoded, char* expected, int length, bool print_results)` | Compares each decoded value with the expected value and returns the number of incorrect values. Optionally prints the results to stdout.
`void libtea_check_decoded_per_cacheline(char* decoded, char* expected, int length)` | Calculates the percentage accuracy per decoded cache line (64 bytes) and prints the results to stdout in CSV format.

Paging Functionality            | Description
--------------------------------|---------------------------------------------
`void set_paging_implementation(libtea_instance* instance, int implementation)` | Switch between kernel and user-space paging implementations. Provide: the libtea instance; the implementation to use (either LIBTEA_PAGING_IMPL_KERNEL, LIBTEA_PAGING_IMPL_USER, or LIBTEA_PAGING_IMPL_USER_PREAD).
`libtea_page_entry libtea_resolve_addr(libtea_instance* instance, void* address, int pid)` | Resolves the page table entries of all levels for a virtual address of a given process. Provide: the libtea instance; the virtual address to resolve; the PID of the process (0 for own process).
`void libtea_update_addr(libtea_instance* instance, void* address, int pid, libtea_page_entry* vm)` | Updates one or more page table entries for a virtual address of a given process. The TLB for the given address is flushed after updating the entries. Provide: the libtea instance; the virtual address to update; the PID of the process (0 for own process); a `libtea_page_entry*` containing the values for the page table entries and a bitmask indicating which entries to update.
`void libtea_set_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit)` | Sets a bit in the page table entry of an address. Provide: the libtea instance; the virtual address; the PID of the process (0 for own process); the bit to set (one of `LIBTEA_PAGE_BIT_*`).
`void libtea_clear_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit)` | Clears a bit in the page table entry of an address. Provide: the libtea instance; the virtual address; the PID of the process (0 for own process); the bit to clear (one of `LIBTEA_PAGE_BIT_*`).
`int libtea_mark_page_present(libtea_instance* instance, void* page, int prot)` | Helper function to mark a page as present and ensure the kernel is aware of this. Linux only. Use in preference to libtea_set_addr_page_bit to avoid system crashes (only necessary for the special case of the present bit). Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`.
`int libtea_mark_page_not_present(libtea_instance* instance, void* page)` | Helper function to mark a page as not present and ensure the kernel is aware of this. Linux only. Use in preference to libtea_clear_addr_page_bit to avoid system crashes (only necessary for the special case of the present bit). Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`.
`unsigned char libtea_get_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit)` | Returns the value of a bit from the page table entry of an address. Provide: the libtea instance; the virtual address; the PID of the process (0 for own process); the bit to get (one of `LIBTEA_PAGE_BIT_*`).
`size_t libtea_get_addr_pfn(libtea_instance* instance, void* address, pid_t pid)` | Reads the page frame number (PFN) from the page table entry of an address. IMPORTANT: check if this has returned 0 before you use the value! On Windows, the PFN will be 0 of the page has not yet been committed (e.g. if you have allocated but not accessed the page). Provide: the libtea instance; the virtual address; the PID of the process (0 for own process).
`void libtea_set_addr_pfn(libtea_instance* instance, void* address, pid_t pid, size_t pfn)` | Sets the PFN in the page table entry of an address. Provide: the libtea instance; the virtual address; the PID of the process (0 for own process); the new PFN.
`libtea_cast(v, type)` | Casts a paging structure entry to a structure with easy access to its fields. Provide: entry to cast; data-type of struct to cast to, e.g. `libtea_pte`. Returns a struct of type "type" with easily-accessible fields.
`size_t libtea_set_pfn(size_t entry, size_t pfn)` | Returns a new page table entry where the PFN is replaced by the specified one.
`size_t libtea_get_pfn(size_t entry)` | Returns the PFN of a page table entry.
`void libtea_read_physical_page(libtea_instance* instance, size_t pfn, char* buffer)` | Retrieves the content of a physical page. Provide: the libtea instance; the PFN of the page to read; a buffer that is at least as large as the page.
`void libtea_write_physical_page(libtea_instance* instance, size_t pfn, char* content)` | Replaces the content of a physical page. Provide: the libtea instance; the PFN of the page to write to; a buffer containing the new content of the page (buffer size must match the size of the page).
`void* libtea_map_physical_address_range(libtea_instance* instance, size_t paddr, size_t length, int prot, bool use_dev_mem)` | Maps a physical address range and returns the address of the mapping. Provide: the libtea instance; the physical address to map; the size of the range to map; the desired memory protection; whether to map from /dev/mem or /dev/umem. Note that /dev/umem does not support PROT_EXEC mappings.
`int libtea_unmap_address_range(size_t vaddr, size_t length)` | Unmaps an address range that was mapped into this process' virtual address space with libtea_map_physical_address_range or libtea_remap_address. Note: Linux only. Provide: the virtual address of the mapping and the length of the range to unmap. Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`.
`void* libtea_remap_address(libtea_instance* instance, size_t vaddr, libtea_page_level level, size_t length, int prot, bool use_dev_mem)` | Creates an additional virtual mapping to the physical address backing the provided virtual address. Provide: the libtea instance; the virtual address; the page level to determine the physical address of; the length of the new mapping; the protection flags to use; whether to map from /dev/mem or /dev/umem. Note that /dev/umem does not support PROT_EXEC mappings.
`size_t libtea_get_paging_root(libtea_instance* instance, pid_t pid)` | Returns the address of the root of the paging structure (i.e., CR3 value on x86 and TTBR0 value on ARM). Provide: the libtea instance; the process ID (0 for own process).
`void libtea_set_paging_root(libtea_instance* instance, pid_t pid, size_t root)` | Sets the root of the paging structure (i.e., CR3 value on x86 and TTBR0 value on ARM). Provide: the libtea instance; the process ID (0 for own process); new physical address for the root of the paging structure.
`void libtea_flush_tlb(libtea_instance* instance, void* address)` | Flushes/invalidates the TLB entry for the provided virtual address on all CPUs.
`void libtea_paging_barrier(libtea_instance* instance)` | A full serializing barrier specifically for paging (overwrites the paging root with its current value).
`int libtea_switch_flush_tlb_implementation(libtea_instance* instance, int implementation)` | Changes the implementation used for flushing the TLB. Both implementations use the kernel module, but `LIBTEA_FLUSH_TLB_KERNEL` uses the native kernel functionality and is much faster; it should be preferred unless your kernel does not support
`flush_tlb_mm_range`. Note: Linux only. Provide: the libtea instance and the implementation to use (either `LIBTEA_FLUSH_TLB_KERNEL` or `LIBTEA_FLUSH_TLB_CUSTOM`). Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`.
`int libtea_get_pagesize(libtea_instance* instance)` | Returns the default page size of the system in bytes.
`uint64_t libtea_get_physical_address_width()` | Returns the physical address width of the CPU. Supported on Linux x86 only.
`size_t libtea_get_physical_address_at_level(libtea_instance* instance, size_t vaddr, libtea_page_level level)` | Returns the physical address of the provided virtual address at the provided paging level. Supported on Linux x86 only.
`size_t libtea_get_memory_types(libtea_instance* instance)` | Reads the value of all memory types (x86 PATs / ARM MAIRs). This is equivalent to reading the MSR 0x277 (x86) / MAIR_EL1 (ARM). Returns the value in the format as in the IA32_PAT MSR / MAIR_EL1.
`void libtea_set_memory_types(libtea_instance* instance, size_t mts)` | Sets the value of all memory types (x86 PATs / ARM MAIRs). This is equivalent to writing to the MSR 0x277 (x86) / MAIR_EL1 (ARM) on all CPUs. Provide the memory types in the same format as in the IA32_PAT MSR / MAIR_EL1.
`char libtea_get_memory_type(libtea_instance* instance, unsigned char mt)` | Returns the value of the provided memory type attribute (PAT/MAIR). Provide: the libtea instance; the PAT/MAIR ID (from 0 to 7).
`void libtea_set_memory_type(libtea_instance* instance, unsigned char mt, unsigned char value)` | Sets the value of the provided memory type attribute (PAT/MAIR). Provide: the libtea instance; the PAT/MAIR ID (from 0 to 7), the PAT/MAIR value (LIBTEA_UNCACHEABLE, LIBTEA_UNCACHEABLE_MINUS, LIBTEA_WRITE_COMBINING, LIBTEA_WRITE_THROUGH, LIBTEA_WRITE_BACK, or LIBTEA_WRITE_PROTECTED).
`unsigned char libtea_find_memory_type(libtea_instance* instance, unsigned char type)` | Generates a bitmask of all memory type attributes (PAT/MAIR) that are programmed to the provided value.
`int libtea_find_first_memory_type(libtea_instance* instance, unsigned char type)` | Returns the first memory type attribute (PAT/MAIR) that is programmed to the provided memory type, or -1 if no PAT/MAIR of this type was found.
`size_t libtea_apply_memory_type(size_t entry, unsigned char mt)` | Returns a new page table entry which uses the provided memory type (PAT/MAIR). Provide: a page table entry; a PAT/MAIR ID (between 0 and 7).
`unsigned char libtea_extract_memory_type(size_tentry)` | Returns the memory type (i.e., PAT/MAIR ID) which is used by a page table entry.
`const char* libtea_memory_type_to_string(unsigned char mt)` | Returns a human-readable representation of a memory type (PAT/MAIR value).
`int libtea_set_page_cacheability(libtea_instance* instance, void* page, unsigned char type)` | Helper function to find and apply the provide memory type (LIBTEA_UNCACHEABLE, LIBTEA_UNCACHEABLE_MINUS, LIBTEA_WRITE_COMBINING, LIBTEA_WRITE_THROUGH, LIBTEA_WRITE_BACK, or LIBTEA_WRITE_PROTECTED) to the page. Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`.
`void libtea_print_libtea_page_entry(libtea_page_entry entry)` | Pretty prints a `libtea_page_entry` struct.
`void libtea_print_page_entry(size_t entry)` | Pretty prints a page table entry.
`void libtea_print_page_entry_line(size_t entry, int line)` | Prints a single line of the pretty-print representation of a page table entry. Provide: a page table entry; the line to print (0 to 3).


Windows-only Functionality            | Description
--------------------------------|---------------------------------------------
`int libtea_isolate_windows_core(int core)` |  Attempts to isolate the provided CPU core by removing it from the affinity mask of all running user processes (Windows-only). This is an experimental function and is only enabled if `LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION` is set to 1 in `libtea_config.h`. Returns `LIBTEA_SUCCESS` or `LIBTEA_ERROR`. On Linux, boot with the `isolcpus=X` parameter set or (preferred) use the `cset-shield` tool.
`long long libtea_force_memory_deduplication()` | Forces a page combining scan across the whole system (Windows-only). Returns the number of pages combined. This is experimental and is only enabled if `LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION` is set to 1 in `libtea_config.h`.


Interrupts Functionality            | Description
--------------------------------|---------------------------------------------
`void libtea_map_gdt(libtea_instance* instance, libtea_gdt* gdt)` | Establishes a user-space mapping for the Global Descriptor Table (GDT). Provide: the libtea instance; an empty GDT which will be filled with the user-space mapped base and current GDT entries.
`void libtea_map_idt(libtea_instance* instance, libtea_idt* idt)` | Establishes a user-space mapping for the Interrupt Descriptor Table (IDT). Provide: the libtea instance; an empty IDT which will be filled with the user-space mapped base and current IDT entries.
`void libtea_print_gdt(libtea_gdt* gdt)` | Prints a Global Descriptor Table (GDT).
`void libtea_print_idt(libtea_idt* idt)` | Prints an Interupt Descriptor Table (IDT).
`void libtea_print_gate_descriptor(libtea_gate_descriptor* gate, int idx)` | Prints a call gate descriptor. Provide: the gate descriptor to print; the index of the descriptor.
`void libtea_print_seg_descriptor(libtea_seg_descriptor* desc, int idx)` | Prints a segment descriptor. Provide: the segment descriptor to print; the index of the descriptor.
`libtea_gate_descriptor* libtea_get_gate_descriptor(libtea_gdt* gdt, int idx)` | Returns the specified gate descriptor from the GDT. Provide: the GDT; the index of the gate descriptor.
`libtea_seg_descriptor* libtea_get_seg_descriptor(libtea_gdt* gdt, int idx)` | Returns the specified segment descriptor from the GDT. Provide: the GDT; the index of the segment descriptor.
`int libtea_get_cpl(void)` | Returns the Current Privilege Level (CPL, or ring).
`void libtea_install_call_gate(libtea_gdt* gdt, int gdt_idx, libtea_cs cs, libtea_call_gate_callback handler)` | Installs a user-space custom call gate. Note: ensure SMAP/SMEP are disabled before using this function. Provide: the GDT; the index to install the call gate at; the code segment for the call gate; the call gate function to register.
`void libtea_do_far_call(int gdt_idx)` | Does a far call to the requested call gate.
`void libtea_install_user_irq_handler(libtea_idt* idt, void* asm_handler, int vector)` | Installs a user-space ASM interrupt handler. Warning: may cause occasional system crashes due to a race condition with the kernel, prefer kernel-space handlers. Provide: the IDT; the ASM handler to register; the IRQ vector.
`void libtea_install_kernel_irq_handler(libtea_idt* idt, void* asm_handler, int vector)` | Installs a kernel-space ASM interrupt handler. Provide: the IDT; the ASM handler to register; the IRQ vector.
`void libtea_exec_in_kernel(libtea_instance* instance, libtea_privileged_callback callback, int cpu)` | Installs and calls a ring 0 IRQ gate. Provide: the libtea instance; a callback containing privileged code to execute in ring 0; the CPU core to install the gate on.
`void libtea_apic_init(libtea_instance* instance)` | Maps APIC timer MMIO registers into user space. Must be run before other APIC functions can be used. Note: you must be booted in xAPIC mode - advised Linux command line parameters are: `nox2apic iomem=relaxed no_timer_check`
`void libtea_apic_timer_oneshot(libtea_instance* instance, uint8_t vector)` | Sets up the APIC timer in one-shot mode. Provide: the libtea instance; the interrupt vector the timer should trigger.
`void libtea_apic_timer_deadline(libtea_instance* instance)` | Sets up the APIC timer in deadline mode.
`void libtea_apic_write(libtea_instance* instance, uint32_t reg, uint32_t value)` | Writes to a local APIC register. Provide: the libtea instance; the register to write to; the value to write.
`void libtea_apic_write_unsafe(uint32_t reg, uint32_t value)` | Writes to a local APIC register. Suitable for use in privileged callbacks as it does not use the libtea instance, but performs no checks to ensure APIC functionality is initialized. Provide: the register to write to; the value to write.
`uint32_t libtea_apic_read(libtea_instance* instance, uint32_t reg)` | Reads from a local APIC register and returns its value. Provide: the libtea instance; the register to read.
`uint32_t libtea_apic_read_unsafe(instance, uint32_t reg)` | Reads from a local APIC register and returns its value. Suitable for use in privileged callbacks as it does not use the libtea instance, but performs no checks to ensure APIC functionality is initialized. Provide: the register to read.

Enclave Functionality            | Description
--------------------------------|---------------------------------------------
`void libtea_register_custom_aep_function(libtea_aep_function_t custom_function)` | Registers a custom function to run during the AEP trampoline (optional). The function can be entirely arbitrary - it does not need to handle any AEP-specific state or tasks.
`void libtea_init_enclave_info(libtea_instance* instance, libtea_enclave_info* enclave)` | Initalizes the provided enclave struct so it can be used by other libtea enclave functions. The struct is initalized using information from SGX.
`void* libtea_get_enclave_base(libtea_enclave_info* enclave)` | Returns a pointer to the base address of the enclave. Provide: an initialized enclave info struct.
`int libtea_get_enclave_size(libtea_enclave_info* enclave)` | Returns the size of the enclave. Provide: an initialized enclave info struct.
`void libtea_print_enclave_info(libtea_instance* instance, libtea_enclave_info* enclave)` | Prints the following information about the enclave to stdout: the address of its base, limit, TCS, SSA-GPRSGX, and AEP; its size; and whether it is a debug or production enclave. Provide: an initialized enclave info struct.
`void* libtea_get_gprsgx_address(libtea_instance* instance, libtea_enclave_info* enclave)` | Returns a pointer to the GPRSGX region in the enclave's SSA frame, where it saves its state upon being interrupted. Provide: the libtea instance; an initialized enclave info struct.
`void libtea_print_gprsgx_state(libtea_gprsgx_state *sgx_state)` | Prints the provided GPRSGX state to stdout.
`void libtea_read_enclave_addr(libtea_instance* instance, void* addr, void* value, int len)` | Reads from an enclave address. Note: only works with debug enclaves. Provide: the libtea instance; the enclave address to read; a variable to write the read value to; the number of bytes to read.
`void libtea_write_enclave_addr(libtea_instance* instance, void* addr, void* value, int len)` | Writes to an enclave address. Note: only works with debug enclaves. Provide: the libtea instance; the enclave address to write; a variable containing the value to write; the number of bytes to write.
`uint64_t libtea_read_ssa_at_offset(libtea_instance* instance, libtea_enclave_info* enclave, int ssa_field_offset)` | Returns the value at the provided offset in the interrupted enclave's SSA frame. Note: only works with debug enclaves. Provide: the libtea instance; an initialized enclave info struct; the offset within the SSA frame.
`uint64_t libtea_get_erip(libtea_instance* instance, libtea_enclave_info* enclave)` | Returns the stored instruction pointer (ERIP) from the interrupted enclave's SSA frame. Note: only works with debug enclaves. Provide: the libtea instance; an initialized enclave info struct.
