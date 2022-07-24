
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_INTERNAL_H
#define LIBTEA_INTERNAL_H

#include <stddef.h>
#include "../libtea_config.h"
#include "libtea_ioctl.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define from_user raw_copy_from_user
#define to_user raw_copy_to_user
#else
#define from_user copy_from_user
#define to_user copy_to_user
#endif

#if LIBTEA_SUPPORT_PAGING

#if LIBTEA_AARCH64
#include <linux/hugetlb.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
typedef pgdval_t p4dval_t;
#endif

void __attribute__((weak)) set_swapper_pgd(pgd_t* pgdp, pgd_t pgd) {}
pgd_t __attribute__((weak)) swapper_pg_dir[PTRS_PER_PGD];

static inline pte_t native_make_pte(pteval_t val)
{
  return __pte(val);
}

static inline pgd_t native_make_pgd(pgdval_t val)
{
  return __pgd(val);
}

static inline pmd_t native_make_pmd(pmdval_t val)
{
  return __pmd(val);
}

static inline pud_t native_make_pud(pudval_t val)
{
  return __pud(val);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static inline p4d_t native_make_p4d(p4dval_t val)
{
  return __p4d(val);
}
#endif

static inline pteval_t native_pte_val(pte_t pte)
{
  return pte_val(pte);
}

static inline int pud_large(pud_t pud) {
#ifdef __PAGETABLE_PMD_FOLDED
    return pud_val(pud) && !(pud_val(pud) & PUD_TABLE_BIT);
#else
    return 0;
#endif
}

static inline int pmd_large(pmd_t pmd) {
#ifdef __PAGETABLE_PMD_FOLDED
    return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT)
#else
    return 0;
#endif
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_KALLSYMS_LOOKUP 1
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func
static struct kprobe kp = {
  .symbol_name	= "kallsyms_lookup_name",
};
#endif

typedef struct {
    size_t pid;
    pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    p4d_t *p4d;
#else
    size_t *p4d;
#endif
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    size_t valid;
} vm_t;

#endif

#define RET_ASSERT(cond)                            \
    do {                                            \
        if (!(cond))                                \
        {                                           \
            printk(KERN_INFO "LIBTEA: assertion '" #cond "' failed."); \
            return -EINVAL;                         \
        }                                           \
    } while(0)

#endif //LIBTEA_INTERNAL_H
