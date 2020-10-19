
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_MODULE_H
#define LIBTEA_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif


#if LIBTEA_LINUX
#define LIBTEA_DEVICE_NAME "libtea"
#define LIBTEA_DEVICE_PATH "/dev/" LIBTEA_DEVICE_NAME


#else
#define LIBTEA_DEVICE_NAME "LibteaLink"
#define LIBTEA_DEVICE_PATH "\\\\.\\" LIBTEA_DEVICE_NAME
#pragma warning(disable : 4201)
#endif


/* Libtea Common Functionality */

#include <stddef.h>   //For size_t

/**
 * Structure to get/set system registers
 */
typedef struct {
    /** Register ID */
    size_t reg;
    /** Logical CPU core to modify the register on */
    int cpu;
    /** Value */
    size_t val;
} libtea_system_reg;


#if LIBTEA_LINUX
#define LIBTEA_IOCTL_MAGIC_NUMBER (long)0x3d17
#define LIBTEA_IOCTL_GET_SYSTEM_REG \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 1, size_t)

#define LIBTEA_IOCTL_SET_SYSTEM_REG \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 2, size_t)

#define LIBTEA_IOCTL_GET_KERNEL_PHYS_ADDR \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 3, size_t)

#else
/* Due to repeated problems with including ntddk.h, manually define our own versions of these */
#define LIBTEA_FILE_DEVICE_UNKNOWN             0x00000022
#define LIBTEA_FILE_ANY_ACCESS                 0
#define LIBTEA_FILE_READ_ACCESS                0x0001
#define LIBTEA_METHOD_BUFFERED                 0
#define LIBTEA_CTL_CODE( DeviceType, Function, Method, Access ) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) )
#define LIBTEA_IOCTL_GET_PHYS_ADDR LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x807, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)
#define LIBTEA_IOCTL_GET_SYSTEM_REG LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x80b, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)
#define LIBTEA_IOCTL_SET_SYSTEM_REG LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x80c, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#endif


#if LIBTEA_SUPPORT_PAGING

#if LIBTEA_LINUX

//Do not modify - these are definitions, not configuration variables.
//Use libtea_switch_flush_tlb_implementation at runtime to choose which to use
#define LIBTEA_FLUSH_TLB_KERNEL 1
#define LIBTEA_FLUSH_TLB_CUSTOM 0

#define LIBTEA_IOCTL_VM_RESOLVE \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 4, size_t)

#define LIBTEA_IOCTL_VM_UPDATE \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 5, size_t)

#define LIBTEA_IOCTL_VM_LOCK \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 6, size_t)

#define LIBTEA_IOCTL_VM_UNLOCK \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 7, size_t)

#define LIBTEA_IOCTL_READ_PAGE \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 8, size_t)

#define LIBTEA_IOCTL_WRITE_PAGE \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 9, size_t)

#define LIBTEA_IOCTL_GET_ROOT \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 10, size_t)

#define LIBTEA_IOCTL_SET_ROOT \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 11, size_t)

#define LIBTEA_IOCTL_GET_PAGESIZE \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 12, size_t)

#define LIBTEA_IOCTL_FLUSH_TLB \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 13, size_t)

#define LIBTEA_IOCTL_GET_PAT \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 14, size_t)

#define LIBTEA_IOCTL_SET_PAT \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 15, size_t)

#define LIBTEA_IOCTL_SWITCH_FLUSH_TLB_IMPLEMENTATION \
  _IOR(LIBTEA_IOCTL_MAGIC_NUMBER, 16, size_t)


#if LIBTEA_SUPPORT_SGX
#define LIBTEA_IOCTL_ENCLAVE_INFO \
  _IOWR(LIBTEA_IOCTL_MAGIC_NUMBER, 17, struct libtea_enclave_info)

#define LIBTEA_IOCTL_EDBGRD \
  _IOWR(LIBTEA_IOCTL_MAGIC_NUMBER, 18, libtea_edbgrd)
#endif

#else

#define LIBTEA_IOCTL_READ_PAGE LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x801, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#define LIBTEA_IOCTL_WRITE_PAGE LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x802, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_READ_ACCESS)

#define LIBTEA_IOCTL_GET_CR3 LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x803, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#define LIBTEA_IOCTL_FLUSH_TLB LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x804, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#define LIBTEA_IOCTL_READ_PHYS_VAL LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x805, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#define LIBTEA_IOCTL_WRITE_PHYS_VAL LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x806, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#define LIBTEA_IOCTL_SET_CR3 LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x808, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#define LIBTEA_IOCTL_SET_PAT LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x809, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#define LIBTEA_IOCTL_GET_PAT LIBTEA_CTL_CODE(LIBTEA_FILE_DEVICE_UNKNOWN, 0x80a, LIBTEA_METHOD_BUFFERED, LIBTEA_FILE_ANY_ACCESS)

#endif


/**
 * Structure containing the page-table entries of all levels.
 * The Linux names are aliased with the Intel names.
 */
typedef struct {
    /** Process ID */
    size_t pid;
    /** Virtual address */
    size_t vaddr;

    /** Page global directory / Page map level 5 */
    union {
        size_t pgd;
        size_t pml5;
    };
    /** Page directory 4 / Page map level 4 */
    union {
        size_t p4d;
        size_t pml4;
    };
    /** Page upper directory / Page directory pointer table */
    union {
        size_t pud;
        size_t pdpt;
    };
    /** Page middle directory / Page directory */
    union {
        size_t pmd;
        size_t pd;
    };
    /** Page table entry */
    size_t pte;
    /** Bitmask indicating which entries are valid/should be updated */
    size_t valid;
} libtea_page_entry;


/**
 * Structure to read/write physical pages
 */
#if LIBTEA_LINUX
typedef struct {
    /** Page-frame number */
    size_t pfn;
    /** Virtual address */
    size_t vaddr;
    /** Page size */
    size_t size;
    /** Page content */
    unsigned char* buffer;
} libtea_physical_page;
#else


#ifdef _MSC_VER
__pragma(pack(push, 1))
#else
#pragma pack(push, 1)
#endif


typedef struct {
    char content[4096];
    size_t paddr;
} libtea_physical_page;


#ifdef _MSC_VER
__pragma(pack(pop))
#else
#pragma pack(pop)
#endif

#endif


/**
 * Structure to get/set the root of paging
 */
typedef struct {
    /** Process id */
    size_t pid;
    /** Physical address of paging root */
    size_t root;
} libtea_paging_root;


#define LIBTEA_VALID_MASK_PGD (1<<0)
#define LIBTEA_VALID_MASK_P4D (1<<1)
#define LIBTEA_VALID_MASK_PUD (1<<2)
#define LIBTEA_VALID_MASK_PMD (1<<3)
#define LIBTEA_VALID_MASK_PTE (1<<4)

#endif


#if LIBTEA_SUPPORT_SGX

#ifndef __KERNEL__
#include <stdint.h>
#endif


struct libtea_enclave_info {
  uint64_t base;
  uint64_t size;
  uint64_t aep;
  uint64_t tcs;
};

typedef struct {
  uint64_t adrs;
  uint64_t val;
  int64_t  len;
  int      write;
} libtea_edbgrd;

typedef struct {
  uint64_t adrs;
} libtea_invpg;


#endif


#ifdef __cplusplus
}
#endif


#endif //LIBTEA_MODULE_H
