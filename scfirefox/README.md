# SCFirefox
**SCFirefox** is a framework for rapid prototyping of browser-based microarchitectural attacks on Linux. It adds attack primitives from **libtea** to Firefox's JavaScript engine, SpiderMonkey, which you can easily call from JavaScript in the browser.

## Build
**SCFirefox** was originally developed with `mozilla-central` changeset `542199:932240e49142` (July 27th 2020). The current patch and framework files have been tested with `mozilla-central` changeset `581403:16915d90a511` (May 29th 2021). However, the files modified in the patch are quite stable and so building **SCFirefox** with both newer and older versions of Firefox should be straightforward, provided the version uses the Mach build system. 

To save space, the source files are not included in the repo, so first follow the download and build instructions here: https://firefox-source-docs.mozilla.org/contributing/contribution_quickref.html. Nightly builds from `mozilla-central` or `mozilla-unified` are inherently a little unstable, so if you have build problems try reverting to an early commit. We use Nightly rather than the release versions as some debug features are only supported in Nightly.

* Apply the **SCFirefox** patch (on Windows, use a Linux shell such as the one provided by the Firefox build bootstrapping process). If the patch fails, try running a fuzzy patch or making the changes by hand; only a few lines of Firefox source code need to be modified.

``` bash
patch -p{n} < scfirefox.patch
```

* Ensure your build of **libtea** is up-to-date (see **libtea** build instructions) and built with the paging configuration (interrupts and enclave functionality are not supported in **SCFirefox**).
* Copy `scfirefox.cpp`, `scfirefox.h`, and `libtea.h` into `mozilla-central/js/src`.
* Additionally, if building on Windows remove the line `'/config/check_spidermonkey_style.py',` from `js/src/build/moz.build`.
* Export the debug `MOZCONFIG`, then in the root directory run the following (note that on Windows, `MOZCONFIG` will be auto-detected if the file is in the root Firefox source directory):

``` bash
export MOZCONFIG="{your path to scfirefox}/MOZCONFIG"
./mach bootstrap
./mach build
```

When prompted to select a build option during the bootstrap process, choose either 2 (Firefox for Desktop without downloaded artifacts) for the full browser or 5 to build just the JS shell (SpiderMonkey). 

By default, the **SCFirefox** `MOZCONFIG` only builds the JS shell rather than the full Firefox browser. To build the full browser, remove the line `ac_add_options --enable-application=js`. To disable all debug options and build a non-debug, optimized release version of the browser, simply do not export the `MOZCONFIG` before building. Before building after modifying the `MOZCONFIG` file, you must clean all build files by running `./mach clobber`, or you will encounter build errors.

To cross-compile (e.g. to build for AArch64 on x86), ensure you have an appropriate cross-compilation toolchain installed and set the target variable in your `MOZCONFIG`, e.g. `ac_add_options --target=aarch64`. You will need a cross-compiled copy of zlib (set the `MOZ_ZLIB_CFLAGS` and `MOZ_ZLIB_LIBS` variables).

Note that the initial build of the full browser takes a very long time and places high load on all CPU cores; your system may be unusable during this time. Subsequent builds (if you only change **SCFirefox** or other `js/src` files) are much faster.

## Usage
* Use `./mach run` to run the JS shell / browser.
* Use the `--debug` argument to run with your system's default debugger, `--no-baseline` to disable the Baseline compiler, and `--no-ion` to disable the IonMonkey optimizing JIT compiler (with both disabled the code will solely be interpreted).
* In order to use `SharedArrayBuffer` in locally-stored files, run `server.py` in the folder containing the files you wish to load and access them at `localhost:8000`. While options do exist in the browser to disable the checks for COOP and COEP headers, these do not appear to fully restore timing resolution, so it is still necessary to provide these HTTP headers (the options are `dom.postMessage.sharedArrayBuffer.withCOOP_COEP` and `dom.postMessage.sharedArrayBuffer.bypassCOOP_COEP.insecure.enabled`, which should be set to true; also set `security.fileuri.strict_origin_policy` to false).
* In order to use **SCFirefox's** kernel functionality, ensure the **libtea** driver is loaded and then run either with `sudo` (on Linux) or from an Administrator command prompt (on Windows). Finally, you will need to disable the sandbox features in `about:config` (in particular, change `security.sandbox.content.level` from 6 to 0). These changes are persistent in the default user profile, so only need to be made once. On Windows, you additionally need to run with the `--no-sandbox` and `--no-deelevate` arguments.
* If you're creating prototypes with long-running loops, you might also want to set `dom.ipc.reportProcessHangs` and  `dom.ipc.processHangMonitor` to false, and set `dom.max_script_run_time` to a high value (in seconds) to avoid popup warnings about the script being unresponsive. You will need to restart Firefox for these changes to take effect.

Using the **SCFirefox** API in JS:

``` javascript
SCFirefox.init();
var buf = new ArrayBuffer(4096);
var arrayView = new Uint8Array(buf)
var addr = SCFirefox.get_virtual_address(arrayView);
var paddr = SCFirefox.get_physical_address(addr);
var accessed = SCFirefox.get_addr_page_bit(addr, 0, SCFirefox.PAGE_BIT_ACCESSED);
console.log("Accessed bit value of arrayView's underlying buffer is currently:", accessed).
SCFirefox.cleanup()
```

NOTE: Due to the complex differences between variables in C and JavaScript, any addresses passed to **SCFirefox** functions *must* be obtained from the `SCFirefox.get_virtual_address(var)` function, rather than passing in a JavaScript variable directly. Currently this function only supports obtaining virtual addresses for JSObject variable types, e.g. typed views on an `ArrayBuffer` (all available integer array types are supported, including unsigned types) as shown in the example above. This does not apply if you are passing the address of a C pointer back to **SCFirefox**, e.g. an address returned by `SCFirefox.map_file`.

The following useful debug functions available in the JS Shell only (see https://developer.mozilla.org/en-US/docs/Mozilla/Projects/SpiderMonkey/Shell_global_objects for more). Note that some of these are only available in Nightly builds configured with a debug `MOZCONFIG`:

* `dis(f)` - disassembles a function into bytecode
* `dissrc(f)` - disassemble into bytecode and show source code lines
* `trap(func, line2pc(func, lineNum), "print("dbgMsg")")` - set a breakpoint
* `untrap(func, line2pc(func, lineNum))` - remove breakpoint
* `objectAddress(obj)` - get virtual address of an object. Does the same as `SCFirefox.get_virtual_address`.
* `sharedAddress(obj)` - get virtual address of a `SharedArrayBuffer`. Does the same as `SCFirefox.get_virtual_address`.
* `addr.toString(16)` - convert a value to a hex string. Helpful for comparing memory addresses.
* `dumpStringRepresentation(str)` - dumps the internal representation of a string. The first address shown is the string's virtual address.
* `dumpObject(obj)` - dumps the internal representation of an object. This works even with primitive types, because (beware!) it first converts them to an object.

## API

Common Functionality            | Description
--------------------------------|---------------------------------------------
`bool init()`            | Initializes **SCFirefox** and underlying **libtea** instance; initializes and acquires kernel module.
`bool init_nokernel()`   | Initializes **SCFirefox** and underlying **libtea** instance without the kernel module (paging, interrupts, and enclave functionality will be disabled).
`void cleanup()`         | Cleans up **SCFirefox** and underlying **libtea** instance; (if necessary) releases kernel module,
`double get_virtual_address(var)`  | Returns the virtual address of a JavaScript `ArrayBufferView`. Note: You *must* pass this address, not the JS variable, to **SCFirefox** functions requiring a vaddr.
`void access(vaddr)`            | Accesses the provided address.
`void access_b(vaddr)`            | Accesses the provided address (with memory barriers).
`void access_illegal(vaddr)`            | Accesses the provided address within a try/catch block to suppress exceptions.
`void access_b_illegal(vaddr)` | Accesses the provided address (with memory barriers) within a try/catch block to suppress exceptions.
`void access_speculative(vaddr)` | Tries to induce a speculative access of the provided address. Success will vary depending on the microarchitecture used.
`void flush(vaddr)` | Flushes the provided address from the cache.
`void flush_b(vaddr)` | Flushes the provided address from the cache (with memory barriers).
`void barrier_start()` | Begins a memory barrier (note that on x86, ending the barrier is unnecessary).
`void barrier_end()` | Ends a memory barrier.
`void speculation_barrier()` | Inserts a speculation barrier.
`double timestamp()` | Returns the current timestamp.
`void measure_start()` | Begin a timing measurement.
`double measure_end()` | Returns the time that has passed since the start of the measurement, and ends the measurement.
`void set_timer(timerNum)` | Set the used timer. Pass 0 for native timer (e.g. `rdtsc`), 1 for native AMD Zen 2, 2 for native AMD Zen, 3 for counting thread, 4 for Linux perf, 5 for monotonic clock.
`void specpoline(functionName)` | Runs the provided function (without arguments) in a specpoline block so that it will only be executed transiently. Only available if the compiler supports inline assembly.
`int get_current_core` |  Returns the ID of the current CPU core, or `LIBTEA_ERROR` on failure
`int get_hyperthread(core)` | Returns the ID of the sibling hyperthread of the provided core (Linux-only).
`void pin_to_core(core)` | Pins the current process to the provided core.
`int get_current_process_id()` | Returns the process ID of the JS shell / current Firefox tab.
`double get_physical_address(addr)` | Returns the physical address of the provided virtual address.
`double get_physical_address_obj(obj)` | Returns the physical address of the provided `ArrayBufferView` object.
`double open_shared_memory(size)` | Opens a shared memory region (provide size in bytes). Only one region can be open at a time. Returns a virtual address to the start of the region.
`void close_shared_memory()` | Close the current shared memory region.
`void start_leaky_thread(type, secret, shared, core)` |  Starts a leaky thread. Provide: the type of leaky thread to create (1 for load loop, 2 for store loop, 3 for `nop` loop); a secret byte value to repeatedly load/store (ignored for nop loop, but you must still provide a value); 1 to use the **SCFirefox** shared memory region, 0 otherwise; a CPU core to lock the thread to.
`void stop_leaky_thread()` | Stops the victim thread initialized with `start_leaky_thread()`. 
`double map(address, size, rw)` | Returns a new mapping to an existing memory-mapped region, or `LIBTEA_ERROR` if an error occurred. Note: You should unmap the allocated region with `scfirefox_munmap()`. Provide: the address of the existing memory-mapped region; the size of the mapping; 0 for a read-only mapping, 1 for write-only (Linux-only), 2 for read-write.
`map_file_by_offset(filename, rw, offset)` | Maps a page of the given file at the defined offset to the program's address space and returns its address (Linux-only). Note: you must keep track of the order in which you open files and unmap them when finished using `scfirefox_munmap_file()`. Provide: filename (the path to the file); 0 for a read-only mapping, 1 for write-only, 2 for read-write; the offset.
`double map_file(filename, rw)` | Maps an entire file and returns its address. Note: You must keep track of the order in which you open files and unmap them when finished using `scfirefox_munmap_file()`. Provide: filename (the path to the file); 0 for a read-only mapping, 1 for write-only, 2 for read-write.
`void munmap_file(index)` | Unmaps a file mapped with **SCFirefox**. Provide the index of the file based on the order you mapped files in. E.g. for 1st file mapped: 0, 2nd: 1, etc.
`int find_index_of_nth_largest_num(list, numEntries, n)` | Returns the index of the nth largest number in the list (note: size_t used for conversion).
`void write_system_reg(core, reg, value)` | Writes to a model-specific register (MSR) / system register. Provide: the CPU core id, the register, the value to write.
`double read_system_reg(core, reg)` | Reads from a model-specific register (MSR) / system register and returns its value. Provide: the CPU core id, the register.
`void disable_hardware_prefetchers()` | Disables all hardware prefetchers (supported on Intel only)
`void enable_hardware_prefetchers()` | Enables all hardware prefetchers (supported on Intel only)
`double scfirefox_malloc(bytes)` | Enables use of `malloc` in Javascript, returning the address of the allocated memory. Provide: the number of bytes to allocate.
`void scfirefox_free(addr)` |  Enables use of `free` in Javascript. Provide: the address to free.
`double scfirefox_mmap(size, rw)` | Creates a new memory mapping and returns its address. Note: you should unmap the allocated region with `scfirefox_munmap()`. Provide: the size of the region to map; 0 for a read-only mapping, 1 for write-only (Linux-only), 2 for read-write.
`void scfirefox_munmap(index)` | Unmaps a memory mapping created with **SCFirefox**. Provide: the index of the mapping based on the order you mapped files/regions in. E.g. for 1st mapped: 0, 2nd: 1, etc.
`void scfirefox_memset(addr, value, size)` | Enables use of `memset` in Javascript, e.g. to initialize mapped memory regions. Provide: the address of the mapped region; integer value to set the memory region to; and the number of bytes to set.
`void scfirefox_sched_yield()` | Enables use of `sched_yield` (or `SwitchToThread` on Windows) in Javascript. Typical usage: briefly suspend an attacker process to allow a victim event to occur.
`double get_instance()` | Returns the address of the **SCFirefox** instance.

Cache Functionality            | Description
--------------------------------|---------------------------------------------
`int get_threshold()` | Returns the current LLC cache miss threshold value.
`void set_threshold(value)` | Sets the current LLC cache miss threshold value. Provide: the new threshold value.
`int flush_reload(addr)` | Performs Flush+Reload on the provided address and returns 1 for cache hit, 0 for cache miss, based on the current threshold.
`int flush_reload_time(addr)` | Performs Flush+Reload on the provided address and returns the access time. Note: as an optimization, uses no memory barriers between timing start/end and access.
`void calibrate_flush_reload()` | Calibrates the threshold to distinguish between a cache hit and cache miss using Flush+Reload.
`void flush_covert_channel()` | Flush all pages of the **SCFirefox** cache covert channel from the cache.
`int get_cache_slice(paddr)` | Returns the cache slice of the provided physical address.
`int get_cache_set(paddr)` | Returns the cache set of the provided physical address.
`void build_eviction_set(paddr)` | Builds an eviction set for the provided physical address. The resulting set is stored internally in the **SCFirefox** instance; it is not returned.
`void evict()` | Runs eviction using the last built eviction set.
`int evict_reload(addr)` | Performs Evict+Reload on the provided address using the last built eviction set. Returns 1 if the address was cached, 0 otherwise, based on the current threshold.
`void calibrate_evict_reload()` | Calibrates the threshold to distinguish between a cache hit and cache miss using Evict+Reload.
`void prime()` | Performs the prime step using the last built eviction set.
`int prime_probe()` | Performs Prime+Probe using the last built eviction set and returns the execution time of the probe step.
`int measure_slice(addr)` | Returns the slice ID of the provided virtual address, as determined by performance counter measurement (requires MSR access; Intel only).
`void cache_encode(value)` | Encodes a single byte into the cache. The value should be passed as a number 0-255.
`void cache_encode_dereference(addr, offset)` | Dereferences an address at the provided offset and encodes the dereferenced value into the cache.
`int cache_decode_from_to(from, to, use_mix)` | Decodes and returns a value in the provided range (inclusive) from the cache, or `LIBTEA_ERROR` if no cache hit was detected. Provide: range start; range end; whether to check the cache covert channel in a non-linear pattern to avoid hardware prefetching effects (pass as boolean). Warning: `use_mix` can destroy the signal on some CPUs; always try without first.
`int cache_decode(use_mix)` | Decodes and returns a value from the cache, or `LIBTEA_ERROR` if no cache hit was detected. Provide: a boolean indicating whether to check the cache covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: `use_mix` can destroy the signal on some CPUs; always try without first.
`int cache_decode_nonull(use_mix)` | Decodes and returns a value from the cache (no null version - ignores 0), or `LIBTEA_ERROR` if no cache hit was detected. Provide: a boolean indicating whether to check the cache covert channel in a non-linear pattern to avoid hardware prefetching effects. Warning: `use_mix` can destroy the signal on some CPUs; always try without first.
`int[] numeric_cache_decode_histogram(iterations, sleep_len, yield, use_mix, offset, from, to)` | Returns a histogram of decoded cache covert channel values over the provided number of iterations as an int array. Provide: the number of iterations to repeat for; the number of microseconds to sleep for between iterations (0 to not sleep); a boolean indicating whether to call `sched_yield()` / `SwitchToThread()` between iterations; a boolean indicating whether to check the covert channel in a non-linear pattern to avoid hardware prefetching effects; the offset to add to the covert channel index to get the actual encoded character (if using <256 entries); the index in the covert channel to start decoding from (inclusive); the index in the covert channel to stop decoding at (inclusive).

Paging Functionality            | Description
--------------------------------|---------------------------------------------
`void set_paging_implementation(impl)` | Switch between kernel and user-space paging implementations. Provide the implementation to use (either 0 for kernel (Linux-only), 1 for user-space `pread`, or 2 for user-space (Linux-only)).
`void set_addr_page_bit(addr, pid, bit)` | Sets a bit in the page table entry (PTE) of an address. Provide: the virtual address; the PID of the process (0 for own process); the bit to set (one of `SCFirefox.PAGE_BIT_*`).
`void clear_addr_page_bit(addr, pid, bit)` | Clears a bit in the PTE of an address. Provide: the virtual address; the PID of the process (0 for own process); the bit to clear (one of `SCFirefox.PAGE_BIT_*`).
`int get_addr_page_bit(addr, pid, bit)` | Returns the value of a bit from the PTE of an address. Provide: the virtual address; the PID of the process (0 for own process); the bit to get (one of `SCFirefox.PAGE_BIT_*`).
`double get_addr_pfn(addr, pid)` | Reads the page frame number (PFN) from the PTE of an address. IMPORTANT: check if this has returned 0 before you use the value! On Windows, the PFN will be 0 of the page has not yet been committed (e.g. if you have allocated but not accessed the page). Provide: the virtual address; the PID of the process (0 for own process).
`void set_addr_pfn(addr, pid, pfn)` | Sets the PFN in the PTE of an address. Provide: the virtual address; the PID of the process (0 for own process); the new PFN.
`int get_pagesize()` | Returns the default page size of the system in bytes.
`void read_physical_page(pfn, buffer)` | Retrieves the content of a physical page. Provide: the PFN of the page to read; a `scfirefox_malloc()` buffer that is at least as large as the page.
`void write_physical_page(pfn, content)` | Replaces the content of a physical page. Provide: the PFN of the page to write to; a `scfirefox_malloc()` buffer containing the new content of the page (buffer size must match the size of the page).
`map_physical_range(paddr, size)` | Maps a physical address range and returns the address of the mapping. Provide: the physical address to map; the size of the range to map.
`double get_paging_root(pid)` | Returns the address of the root of the paging structure (i.e., CR3 value on x86 and TTBR0 value on ARM). Provide: the process ID (0 for own process).
`void set_paging_root(pid, root)` | Sets the root of the paging structure (i.e., CR3 value on x86 and TTBR0 value on ARM). Provide: the process ID (0 for own process); new address for the root of the paging structure.
`void invalidate_tlb(addr)` | Invalidates the TLB entry for the provided virtual address on all CPUs.
`void paging_barrier()` | A full serializing barrier specifically for paging (overwrites the paging root with its current value).
`double get_memory_types()` | Reads the value of all memory types (x86 PATs / ARM MAIRs). This is equivalent to reading the MSR `0x277` (x86) / `MAIR_EL1` (ARM). Returns the value in the format as in the `IA32_PAT` MSR / `MAIR_EL1`.
`void set_memory_types(mts)` | Sets the value of all memory types (x86 PATs / ARM MAIRs). This is equivalent to writing to the MSR `0x277` (x86) / `MAIR_EL1` (ARM) on all CPUs. Provide the memory types in the same format as in the `IA32_PAT` MSR / `MAIR_EL1`.
`int get_memory_type(mt)` | Returns the value of the provided memory type attribute (PAT/MAIR). Provide: the PAT/MAIR ID (from 0 to 7).
`void set_memory_type(mt, value)` | Sets the value of the provided memory type attribute (PAT/MAIR). Provide: the PAT/MAIR ID (from 0 to 7), the PAT/MAIR value (one of `SCFirefox.MT_*`).
`int find_memory_type(mt)` | Generates a bitmask of all memory type attributes (PAT/MAIR) that are programmed to the provided value. Provide: a memory type (one of `SCFirefox.MT_*`).
`int find_first_memory_type(mt)` | Returns the first memory type attribute (PAT/MAIR) that is programmed to the provided memory type, or -1 if no PAT/MAIR of this type was found. Provide: a memory type (one of `SCFirefox.MT_*`).
`double apply_memory_type(entry, mt)` | Returns a new page table entry which uses the provided memory type (PAT/MAIR). Provide: a page table entry, a PAT/MAIR ID (between 0 and 7).
`int extract_memory_type(entry)` | Returns the memory type (i.e., PAT/MAIR ID) which is used by a page table entry. Provide: a page table entry.
`string memory_type_to_string(mt)` | Returns a human-readable representation of a memory type (PAT/MAIR value). Provide: a memory type (one of `SCFirefox.MT_*`).
`void print_page_entry(addr)` | Prints a page table entry to the command prompt (not to the JS console!). Provide: the virtual address.

Windows-only Functionality            | Description
--------------------------------|---------------------------------------------
`void pin_thread_to_core(core)` | Pins the current thread to the provided core (Windows-only).
`void add_windows_exception_handler()` | Add an exception handler for all exception types (Windows-only). The handler will jump to the next instruction after the faulting instruction.
`void remove_windows_exception_handler()` | Remove an exception handler added with **SCFirefox** (Windows-only).
`clear_windows_working_set()` | Tell Windows to trim as many pages as possible from the current process. Provides a method to clear a page's accessed bit (not guaranteed, but likely to occur) without the **libtea** driver.
`lock_windows_page(address)` | Lock the provided page with `VirtualLock` (Windows-only).
`unlock_windows_page(address)` | Unlock the provided page with `VirtualUnlock` (Windows-only).
`isolate_windows_core(core)` |  Attempts to isolate the provided CPU core by removing it from the affinity mask of all running user processes (Windows-only). This is an experimental function and is only enabled if `LIBTEA_ENABLE_WINDOWS_CORE_ISOLATION` is set to 1 in `libtea_config.h`. Returns `LIBTEA_SUCCESS` on success, otherwise `LIBTEA_ERROR`.
`force_memory_deduplication()` | Forces a page combining scan across the whole system (Windows-only). This is experimental and is only enabled if `LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION` is set to 1 in `libtea_config.h`. Returns the number of pages combined.
