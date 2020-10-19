
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_X86_PAGING_H
#define LIBTEA_X86_PAGING_H

#ifdef __cplusplus
extern "C" {
#endif


#if LIBTEA_X86


/** Page is present */
#define LIBTEA_PAGE_BIT_PRESENT 0
/** Page is writeable */
#define LIBTEA_PAGE_BIT_RW 1
/** Page is userspace addressable */
#define LIBTEA_PAGE_BIT_USER 2
/** Page write through */
#define LIBTEA_PAGE_BIT_PWT 3
/** Page cache disabled */
#define LIBTEA_PAGE_BIT_PCD 4
/** Page was accessed (raised by CPU) */
#define LIBTEA_PAGE_BIT_ACCESSED 5
/** Page was written to (raised by CPU) */
#define LIBTEA_PAGE_BIT_DIRTY 6
/** 4 MB (or 2MB) page */
#define LIBTEA_PAGE_BIT_PSE 7
/** PAT (only on 4KB pages) */
#define LIBTEA_PAGE_BIT_PAT 7
/** Global TLB entry PPro+ */
#define LIBTEA_PAGE_BIT_GLOBAL 8
/** Available for programmer */
#define LIBTEA_PAGE_BIT_SOFTW1 9
/** Available for programmer */
#define LIBTEA_PAGE_BIT_SOFTW2 10
/** Windows only: Prototype PTE. PTE is actually a "symlink" to an OS-managed Prototype PTE shared between multiple processes. This enables working set trimming of shared memory. */
#define LIBTEA_PAGE_BIT_PROTOTYPE LIBTEA_PAGE_BIT_SOFTW2
/** Available for programmer */
#define LIBTEA_PAGE_BIT_SOFTW3 11
/** Windows only: Transition PTE. The data is still valid, but the OS has cleared the present bit in anticipation of removing the page from the process' working set. */
#define LIBTEA_PAGE_BIT_TRANSITION LIBTEA_PAGE_BIT_SOFTW3
/** PAT (on 2MB or 1GB pages) */
#define LIBTEA_PAGE_BIT_PAT_LARGE 12
/** Available for programmer */
#define LIBTEA_PAGE_BIT_SOFTW4 58
/** Protection Keys, bit 1/4 */
#define LIBTEA_PAGE_BIT_PKEY_BIT0 59
/** Protection Keys, bit 2/4 */
#define LIBTEA_PAGE_BIT_PKEY_BIT1 60
/** Protection Keys, bit 3/4 */
#define LIBTEA_PAGE_BIT_PKEY_BIT2 61
/** Protection Keys, bit 4/4 */
#define LIBTEA_PAGE_BIT_PKEY_BIT3 62
/** No execute: only valid after cpuid check */
#define LIBTEA_PAGE_BIT_NX 63


/** Strong uncachable (nothing is cached, strong memory ordering, no speculative reads) */
#define LIBTEA_UNCACHEABLE        0
/** Write combining (consecutive writes are combined in a WC buffer and then written once, allows speculative reads, weak memory ordering) */
#define LIBTEA_WRITE_COMBINING    1
/** Write through (read accesses are cached, write accesses are written to cache and memory, allows speculative reads, speculative processor ordering) */
#define LIBTEA_WRITE_THROUGH      4
/** Write protected (only read accesses are cached, allows speculative reads, speculative processor ordering) */
#define LIBTEA_WRITE_PROTECTED    5
/** Write back (read and write accesses are cached, allows speculative reads, speculative processor ordering) */
#define LIBTEA_WRITE_BACK         6
/** Uncachable minus / UC- (same as strong uncacheable, except this setting can be overridden to write-combining using the MTRRs) */
#define LIBTEA_UNCACHEABLE_MINUS  7

#define LIBTEA_PAGE_PRESENT 1


// Returns a mask of the form:
// +----- n+1 -+- n --------- 0-+
// | 0  0  0   |  1  1  1  1  1 |
// +-----------+----------------+
#define LIBTEA_MASK_TO(m)			    ((UINT64_C(0x1) << ((m) + 1)) - 1 )

// Returns a mask of the form:
// +----- m+1 -+- m ------ n -+--- 0-+
// | 0  0  0   |  1  1  1  1  | 0  0 |
// +-----------+--------------+------+
// The ordered version requires n < m, the other CREATE_MASK checks this at runtime
#define LIBTEA_CREATE_MASK_ORDERED(n,m)	(LIBTEA_MASK_TO((m)) ^ (LIBTEA_MASK_TO((n)) >> 1))
#define LIBTEA_CREATE_MASK(n,m)			(((n) < (m)) ? (LIBTEA_CREATE_MASK_ORDERED((n), (m))) : (LIBTEA_CREATE_MASK_ORDERED((m), (n))))
#define M			                    (libtea_get_physical_address_width())
#define MASK_M			                ((uint64_t) ((INT64_C(0x1) << M) - 1))

#define LIBTEA_PUD_PS_SHIFT		        7
#define LIBTEA_PUD_PS_MASK		        (UINT64_C(0x1) << LIBTEA_PUD_PS_SHIFT)

#define LIBTEA_PMD_PS_SHIFT		        7
#define LIBTEA_PMD_PS_MASK		        (UINT64_C(0x1) << LIBTEA_PMD_PS_SHIFT)

#define LIBTEA_PTE_PHYS_SHIFT	        12
#define LIBTEA_PTE_PHYS_MASK	        (MASK_M << LIBTEA_PTE_PHYS_SHIFT)

#define LIBTEA_PGD_SHIFT		        39
#define LIBTEA_PGD_MASK			        (INT64_C(0x1ff) << LIBTEA_PGD_SHIFT)

#define LIBTEA_PUD_SHIFT		        30
#define LIBTEA_PUD_MASK			        (INT64_C(0x1ff) << LIBTEA_PUD_SHIFT)

#define LIBTEA_PMD_SHIFT		        21
#define LIBTEA_PMD_MASK			        (INT64_C(0x1ff) << LIBTEA_PMD_SHIFT)

#define LIBTEA_PTE_SHIFT		        12
#define LIBTEA_PTE_MASK			        (INT64_C(0x1ff) << LIBTEA_PTE_SHIFT)

#define LIBTEA_PAGE_SHIFT		        0
#define LIBTEA_PAGE_MASK		        (INT64_C(0xfff) << LIBTEA_PAGE_SHIFT)

#define LIBTEA_PAGE1GiB_SHIFT		    0
#define LIBTEA_PAGE1GiB_MASK		    (INT64_C(0x3FFFFFFF) << LIBTEA_PAGE1GiB_SHIFT)

#define LIBTEA_PAGE2MiB_SHIFT		    0
#define LIBTEA_PAGE2MiB_MASK		    (INT64_C(0x1FFFFF) << LIBTEA_PAGE2MiB_SHIFT)

#define LIBTEA_PAGE_SIZE_4KiB		    0x1000
#define LIBTEA_PAGE_SIZE_2MiB		    0x200000
#define LIBTEA_PAGE_SIZE_1GiB		    0x40000000

#define LIBTEA_PUD_PS(entry)			(((entry) & LIBTEA_PUD_PS_MASK) >> LIBTEA_PUD_PS_SHIFT)
#define LIBTEA_PMD_PS(entry)			(((entry) & LIBTEA_PMD_PS_MASK) >> LIBTEA_PMD_PS_SHIFT)

#define LIBTEA_PGD_PHYS(entry)			((entry) & (LIBTEA_CREATE_MASK(12, M-1)))
#define LIBTEA_PUD_PS_0_PHYS(entry)    	((entry) & (LIBTEA_CREATE_MASK(12, M-1)))
#define LIBTEA_PUD_PS_1_PHYS(entry)		((entry) & (LIBTEA_CREATE_MASK(30, M-1)))
#define LIBTEA_PMD_PS_0_PHYS(entry)		((entry) & (LIBTEA_CREATE_MASK(12, M-1)))
#define LIBTEA_PMD_PS_1_PHYS(entry)		((entry) & (LIBTEA_CREATE_MASK(21, M-1)))
#define LIBTEA_PT_PHYS(entry)			((entry) & (LIBTEA_CREATE_MASK(12, M-1)))

#define LIBTEA_PGD_INDEX(vaddr)			(vaddr & LIBTEA_PGD_MASK) >> LIBTEA_PGD_SHIFT
#define LIBTEA_PUD_INDEX(vaddr)			(vaddr & LIBTEA_PUD_MASK) >> LIBTEA_PUD_SHIFT
#define LIBTEA_PMD_INDEX(vaddr)			(vaddr & LIBTEA_PMD_MASK) >> LIBTEA_PMD_SHIFT
#define LIBTEA_PTE_INDEX(vaddr)			(vaddr & LIBTEA_PTE_MASK) >> LIBTEA_PTE_SHIFT
#define LIBTEA_PAGE_INDEX(vaddr)		(vaddr & LIBTEA_PAGE_MASK) >> LIBTEA_PAGE_SHIFT
#define LIBTEA_PAGE1GiB_INDEX(vaddr)	(vaddr & LIBTEA_PAGE1GiB_MASK) >> LIBTEA_PAGE1GiB_SHIFT
#define LIBTEA_PAGE2MiB_INDEX(vaddr)	(vaddr & LIBTEA_PAGE2MiB_MASK) >> LIBTEA_PAGE2MiB_SHIFT


/**
 * Struct to access the fields of the PGD
 */
#pragma pack(push,1)
typedef struct {
    size_t present : 1;
    size_t writeable : 1;
    size_t user_access : 1;
    size_t write_through : 1;
    size_t cache_disabled : 1;
    size_t accessed : 1;
    size_t ignored_3 : 1;
    size_t size : 1;
    size_t ignored_2 : 4;
    size_t pfn : 28;
    size_t reserved_1 : 12;
    size_t ignored_1 : 11;
    size_t execution_disabled : 1;
} libtea_pgd;
#pragma pack(pop)


/**
 * Struct to access the fields of the P4D
 */
typedef libtea_pgd libtea_p4d;


/**
 * Struct to access the fields of the PUD
 */
typedef libtea_pgd libtea_pud;


/**
 * Struct to access the fields of the PMD
 */
typedef libtea_pgd libtea_pmd;


/**
 * Struct to access the fields of the PMD when mapping a large page (2MB)
 */
#pragma pack(push,1)
typedef struct {
    size_t present : 1;
    size_t writeable : 1;
    size_t user_access : 1;
    size_t write_through : 1;
    size_t cache_disabled : 1;
    size_t accessed : 1;
    size_t dirty : 1;
    size_t size : 1;
    size_t global : 1;
    size_t ignored_2 : 3;
    size_t pat : 1;
    size_t reserved_2 : 8;
    size_t pfn : 19;
    size_t reserved_1 : 12;
    size_t ignored_1 : 11;
    size_t execution_disabled : 1;
} libtea_pmd_large;
#pragma pack(pop)


/**
 * Struct to access the fields of the PTE
 */
#pragma pack(push,1)
typedef struct {
    size_t present : 1;                     /* Windows note: if present==1 this is a hardware PTE and we can handle it like a normal PTE. Other notes below only apply when present==0. */
    size_t writeable : 1;
    size_t user_access : 1;
    size_t write_through : 1;
    size_t cache_disabled : 1;
    size_t accessed : 1;
    size_t dirty : 1;
    size_t size : 1;
    size_t global : 1;
    size_t ignored_2 : 3;                   /* Windows note (only if valid==0): if bit 10 is set and not bit 11, it is a Prototype PTE. If bit 11 is set and not bit 10, it is a Transition PTE. If neither are set, it is a Software PTE (paged out to page file). */
    size_t pfn : 28;
    size_t reserved_1 : 12;
    size_t ignored_1 : 11;
    size_t execution_disabled : 1;
} libtea_pte;
#pragma pack(pop)


#endif //LIBTEA_X86

#ifdef __cplusplus
}
#endif

#endif //LIBTEA_X86_PAGING_H