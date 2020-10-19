
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_PAGING_H
#define LIBTEA_PAGING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libtea_common.h"
#include "module/libtea_ioctl.h"

#if defined(_MSC_VER) && (!defined(MOZJS_MAJOR_VERSION) || MOZJS_MAJOR_VERSION < 63)   /* If using Visual Studio C++ compiler. We have to explicitly exclude Firefox after MOZJS v63 as they use the hybrid clang-cl */
#define LIBTEA_PAGE_ALIGN_CHAR __declspec(align(4096)) char
#else                                                                                  /* Assume using GCC, MinGW GCC, or Clang */
#define LIBTEA_PAGE_ALIGN_CHAR char __attribute__((aligned(4096)))
#endif


/* Assumptions - will not be true on less common arches */
#define LIBTEA_PFN_MASK                	0xfffULL
unsigned char libtea_page_shift = 12;


int libtea__paging_init(libtea_instance* instance);


/** Use the kernel to resolve and update paging structures */
#define LIBTEA_PAGING_IMPL_KERNEL       0
/** Use the user-space implemenation to resolve and update paging structures, using pread to read from the memory mapping */
#define LIBTEA_PAGING_IMPL_USER_PREAD   1
/** Use the user-space implementation that maps physical memory into user space to resolve and update paging structures */
#define LIBTEA_PAGING_IMPL_USER         2


typedef libtea_page_entry(*libtea_resolve_addr_func)(libtea_instance*, void*, pid_t);
typedef void (*libtea_update_addr_func)(libtea_instance*, void*, pid_t, libtea_page_entry*);
void libtea__cleanup_paging(libtea_instance* instance);


/**
 * Switch between kernel and user-space paging implementations.
 *
 * :param instance: The libtea instance
 * :param implementation: The implementation to use, either LIBTEA_PAGING_IMPL_KERNEL, LIBTEA_PAGING_IMPL_USER, or LIBTEA_PAGING_IMPL_USER_PREAD
 */
void libtea_set_paging_implementation(libtea_instance* instance, int implementation);


/**
 * Resolves the page table entries of all levels for a virtual address of a given process.
 *
 * :param instance: The libtea instance
 * :param address: The virtual address to resolve
 * :param pid: The PID of the process (0 for own process)
 *
 * :return: A structure containing the page table entries of all levels.
 */
libtea_resolve_addr_func libtea_resolve_addr;


/**
 * Updates one or more page table entries for a virtual address of a given process.
 * The TLB for the given address is flushed after updating the entries.
 *
 * :param instance: The libtea instance
 * :param address: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param vm: A structure containing the values for the page table entries and a bitmask indicating which entries to update
 */
libtea_update_addr_func libtea_update_addr;


/**
 * Sets a bit in the page table entry of an address.
 *
 * :param instance: The libtea instance
 * :param address: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param bit: The bit to set (one of LIBTEA_PAGE_BIT_*)
 */
void libtea_set_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit);


/**
 * Clears a bit in the page table entry of an address.
 *
 * :param instance: The libtea instance
 * :param address: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param bit: The bit to clear (one of LIBTEA_PAGE_BIT_*)
 */
void libtea_clear_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit);


/**
 * Helper function to mark a page as present and ensure the kernel is aware of this.
 * Linux only. Use in preference to libtea_set_addr_page_bit to avoid system crashes
 * (only necessary for the special case of the present bit). 
 *
 * :param instance: The libtea instance
 * :param page: A pointer to the page (must be mapped within the current process)
 * :param prot: The mprotect protection flags to reapply to the page, e.g. PROT_READ
 * :return: LIBTEA_SUCCESS on success, else LIBTEA_ERROR
 */
int libtea_mark_page_present(libtea_instance* instance, void* page, int prot);


/**
 * Helper function to mark a page as not present and ensure the kernel is aware of this.
 * Linux only. Use in preference to libtea_clear_addr_page_bit to avoid system crashes
 * (only necessary for the special case of the present bit). 
 *
 * :param instance: The libtea instance
 * :param page: A pointer to the page (must be mapped within the current process)
 * :return: LIBTEA_SUCCESS on success, else LIBTEA_ERROR
 */
int libtea_mark_page_not_present(libtea_instance* instance, void* page);


/**
 * Returns the value of a bit from the page table entry of an address.
 *
 * :param instance: The libtea instance
 * :param address: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param bit: The bit to get (one of LIBTEA_PAGE_BIT_*)
 *
 * :return: The value of the bit (0 or 1)
 *
 */
unsigned char libtea_get_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit);

/**
 * Reads the page frame number (PFN) from the page table entry of an address.
 *
 * IMPORTANT: check if this has returned 0 before you use the value!
 * On Windows, the PFN will be 0 of the page has not yet been committed
 * (e.g. if you have allocated but not accessed the page).
 *
 * :param instance: The libtea instance
 * :param address: The virtual address
 * :param pid: The PID of the process (0 for own process)
 *
 * :return: The PFN
 */
size_t libtea_get_addr_pfn(libtea_instance* instance, void* address, pid_t pid);

/**
 * Sets the PFN in the page table entry of an address.
 *
 * :param instance: The libtea instance
 * :param address: The virtual address
 * :param pid: The PID of the process (0 for own process)
 * :param pfn: The new PFN
 *
 */
void libtea_set_addr_pfn(libtea_instance* instance, void* address, pid_t pid, size_t pfn);


/**
 * Casts a paging structure entry to a structure with easy access to its fields.
 *
 * :param v: Entry to Cast
 * :param type: Data type of struct to cast to, e.g., libtea_pte
 *
 * :return: Struct of type "type" with easily-accessible fields
 */
#define libtea_cast(v, type) (*((type*)(&(v))))


/**
 * Returns a new page table entry where the PFN is replaced by the specified one.
 *
 * :param entry: The page table entry to modify
 * :param pfn: The new PFN
 *
 * :return: A new page table entry with the given PFN
 */
size_t libtea_set_pfn(size_t entry, size_t pfn);


/**
 * Returns the PFN of a page table entry.
 *
 * :param entry: The page table entry to extract the PFN from
 *
 * :return: The PFN
 */
size_t libtea_get_pfn(size_t entry);


/**
 * Retrieves the content of a physical page.
 *
 * :param instance: The libtea instance
 * :param pfn: The PFN of the page to read
 * :param buffer: A buffer that is large enough to hold the content of the page
 */
void libtea_read_physical_page(libtea_instance* instance, size_t pfn, char* buffer);


/**
 * Replaces the content of a physical page.
 *
 * :param instance: The libtea instance
 * :param pfn: The PFN of the page to update
 * :param content: A buffer containing the new content of the page (must be the size of the physical page)
 */
void libtea_write_physical_page(libtea_instance* instance, size_t pfn, char* content);


/**
 * Map a physical address range into this process' virtual address space.
 *
 * :param instance: The libtea instance
 * :param paddr: The physical address of the start of the range
 * :param length: The length of the physical memory range to map
 * :param prot: The memory protection settings for the virtual mapping (e.g. PROT_READ | PROT_WRITE)
 * :param use_dev_mem: Map with /dev/mem if true, else use libtea_umem. (Only /dev/mem supports PROT_EXEC.)
 * :return: A virtual address that can be used to access the physical range
 */
void* libtea_map_physical_address_range(libtea_instance* instance, size_t paddr, size_t length, int prot, bool use_dev_mem);


/**
 * Unmaps an address range that was mapped into this process' virtual address space with libtea_map_physical_address_range or
 * libtea_remap_address.
 * 
 * Note: supported on Linux only.
 *
 * :param vaddr: The virtual address of the mapping
 * :param length: The length of the range to unmap
 * :return: LIBTEA_SUCCESS on success, else LIBTEA_ERROR
 */
int libtea_unmap_address_range(size_t vaddr, size_t length);


/**
 * Creates an additional virtual mapping to the physical page backing the provided virtual address.
 * Uses libtea_get_physical_address_at_level internally, so can be used with addresses not in the
 * process' pagemap. Use libtea_unmap_address_range to free the mapping.
 * 
 * Note: supported on Linux x86 only.
 *
 * :param instance: The libtea instance
 * :param vaddr: The virtual address to remap
 * :param level: The page table level to resolve the address at
 * :param length: The length of the range to map
 * :param prot: The memory protection to use, e.g. PROT_READ
 * :param use_dev_mem: Map with /dev/mem if true, else use libtea_umem. (Only /dev/mem supports PROT_EXEC.)
 * :return: An additional virtual address for the underlying physical address, or MAP_FAILED on error
 */
void* libtea_remap_address(libtea_instance* instance, size_t vaddr, libtea_page_level level, size_t length, int prot, bool use_dev_mem);


/**
 * Returns the root of the paging structure (i.e., the value of CR3 on x86 / TTBR0 on ARM).
 *
 * :param instance: The libtea instance
 * :param pid: The process id (0 for own process)
 * :return: The paging root, i.e. the physical address of the first page table (i.e., the PGD)
 */
size_t libtea_get_paging_root(libtea_instance* instance, pid_t pid);


/**
 * Sets the root of the paging structure (i.e., the value of CR3 on x86 / TTBR0 on ARM).
 *
 * :param instance: The libtea instance
 * :param pid: The proccess id (0 for own process)
 * :param root: The new paging root, i.e. the new physical address of the first page table (i.e., the PGD)
 */
void libtea_set_paging_root(libtea_instance* instance, pid_t pid, size_t root);


/**
 * Flushes/invalidates the TLB for a given address on all CPUs.
 *
 * :param instance: The libtea instance
 * :param address: The address to invalidate
 */
void libtea_flush_tlb(libtea_instance* instance, void* address);


/**
 * A full serializing barrier specifically for paging (overwrites the paging root with its current value).
 *
 * :param instance: The libtea instance
 */
void libtea_paging_barrier(libtea_instance* instance);


/**
 * Changes the implementation used for flushing the TLB. Both implementations use the kernel module, but LIBTEA_FLUSH_TLB_KERNEL
 * uses the native kernel functionality and is much faster; it should be preferred unless your kernel does not support
 * flush_tlb_mm_range.
 *
 * Note: supported on Linux only.
 *
 * :param instance: The libtea instance
 * :param implementation: The implementation to use, either LIBTEA_FLUSH_TLB_KERNEL or LIBTEA_FLUSH_TLB_CUSTOM
 *
 * :return: LIBTEA_SUCCESS on success, otherwise LIBTEA_ERROR
 */
int libtea_switch_flush_tlb_implementation(libtea_instance* instance, int implementation);


/**
 * Returns the default page size of the system.
 *
 * :param instance: The libtea instance
 * :return: Page size of the system in bytes
 */
int libtea_get_pagesize(libtea_instance* instance);


/**
 * Returns the physical address width.
 * 
 * Note: supported on Linux x86 only.
 *
 * :return: Physical address width of the CPU
 */
uint64_t libtea_get_physical_address_width();


/**
 * Gets the physical address of the provided virtual address at the provided paging level.
 * Currently only supported on Linux x86.
 *
 * :param instance: The libtea instance
 * :param vaddr: The virtual address
 * :param level: Page level to resolve the physical address of
 * :return: The physical address
 */
size_t libtea_get_physical_address_at_level(libtea_instance* instance, size_t vaddr, libtea_page_level level);


/**
 * Reads the value of all memory types (x86 PATs / ARM MAIRs). This is equivalent to reading the MSR 0x277 (x86) / MAIR_EL1 (ARM).
 *
 * :param: The libtea instance
 * :return: The memory types in the same format as in the IA32_PAT MSR / MAIR_EL1
 */
size_t libtea_get_memory_types(libtea_instance* instance);


/**
 * Programs the value of all memory types (x86 PATs / ARM MAIRs). This is equivalent to writing to the MSR 0x277 (x86) / MAIR_EL1 (ARM) on all CPUs.
 *
 * :param instance: The libtea instance
 * :param mts: The memory types in the same format as in the IA32_PAT MSR / MAIR_EL1
 */
void libtea_set_memory_types(libtea_instance* instance, size_t mts);


/**
 * Reads the value of a specific memory type attribute (PAT/MAIR).
 *
 * :param instance: The libtea instance
 * :param mt: The PAT/MAIR ID (from 0 to 7)
 * :return: The PAT/MAIR value (LIBTEA_UNCACHEABLE, LIBTEA_UNCACHEABLE_MINUS,
                LIBTEA_WRITE_COMBINING, LIBTEA_WRITE_THROUGH, LIBTEA_WRITE_BACK,
                or LIBTEA_WRITE_PROTECTED)
 */
char libtea_get_memory_type(libtea_instance* instance, unsigned char mt);


/**
 * Programs the value of a specific memory type attribute (PAT/MAIR).
 *
 * :param instance: The libtea instance
 * :param mt: The PAT/MAIR ID (from 0 to 7)
 */
void libtea_set_memory_type(libtea_instance* instance, unsigned char mt, unsigned char value);


/**
 * Generates a bitmask of all memory type attributes (PAT/MAIR) which are programmed to the given value.
 *
 * :param instance: The libtea instance
 * :param type: A memory type (LIBTEA_UNCACHEABLE, LIBTEA_UNCACHEABLE_MINUS,
                LIBTEA_WRITE_COMBINING, LIBTEA_WRITE_THROUGH, LIBTEA_WRITE_BACK,
                or LIBTEA_WRITE_PROTECTED)
 *
 * :return: A bitmask where a set bit indicates that the corresponding PAT/MAIR has the given type
 */
unsigned char libtea_find_memory_type(libtea_instance* instance, unsigned char type);


/**
 * Returns the first memory type attribute (PAT/MAIR) that is programmed to the given memory type.
 *
 * :param instance: The libtea instance
 * :param type: A memory type (LIBTEA_UNCACHEABLE, LIBTEA_UNCACHEABLE_MINUS,
                LIBTEA_WRITE_COMBINING, LIBTEA_WRITE_THROUGH, LIBTEA_WRITE_BACK,
                or LIBTEA_WRITE_PROTECTED)
 *
 * :return: A PAT/MAIR ID, or -1 if no PAT/MAIR of this type was found
 */
int libtea_find_first_memory_type(libtea_instance* instance, unsigned char type);


/**
 * Returns a new page table entry which uses the given memory type (PAT/MAIR).
 *
 * :param entry: A page table entry
 * :param mt: The PAT/MAIR ID (from 0 to 7)
 *
 * :return: A new page table entry with the given memory type (PAT/MAIR)
 */
size_t libtea_apply_memory_type(size_t entry, unsigned char mt);


/**
 * Sets the memory type of the page to the specified type, e.g. LIBTEA_UNCACHEABLE
 * for strong uncacheable or LIBTEA_WRITE_BACK for write back caching.
 *
 * :param instance: The libtea instance
 * :param page: A pointer to the page
 * :param type: A memory type (LIBTEA_UNCACHEABLE, LIBTEA_UNCACHEABLE_MINUS,
                LIBTEA_WRITE_COMBINING, LIBTEA_WRITE_THROUGH, LIBTEA_WRITE_BACK, 
                or LIBTEA_WRITE_PROTECTED)
 *
 * :return: LIBTEA_SUCCESS on success, else LIBTEA_ERROR
 */
int libtea_set_page_cacheability(libtea_instance* instance, void* page, unsigned char type);


/**
 * Returns the memory type (i.e., PAT/MAIR ID) which is used by a page table entry.
 *
 * :param entry: A page table entry
 *
 * :return: A PAT/MAIR ID (between 0 and 7)
 */
unsigned char libtea_extract_memory_type(size_t entry);


/**
 * Returns a human-readable representation of a memory type (PAT/MAIR value).
 *
 * :param mt: A PAT/MAIR ID
 *
 * :return: A human-readable representation of the memory type
 */
const char* libtea_memory_type_to_string(unsigned char mt);


/**
 * Pretty prints a libtea_page_entry struct.
 *
 * :param entry: A libtea_page_entry struct
 */
void libtea_print_libtea_page_entry(libtea_page_entry entry);


/**
 * Pretty prints a page table entry.
 *
 * :param entry: A page table entry
 */
void libtea_print_page_entry(size_t entry);


/**
 * Prints a single line of the pretty-print representation of a page table entry.
 *
 * :param entry: A page table entry
 * :param line: The line to print (0 to 3)
 */
#define libtea_print_page_entry_line(entry, line)  libtea__arch_print_page_entry_line(entry, line)


/**
 * Forces a page combining scan across the whole system (Windows-only).
 * This is experimental and is only enabled if LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION
 * is set to 1 in libtea_config.h.
 *
 * :return: The number of pages combined
 */
#if LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION
long long libtea_force_memory_deduplication();
#endif


#ifdef __cplusplus
}
#endif

#endif //LIBTEA_PAGING_H
