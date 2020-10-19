
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_PAGING_INTERNAL_H
#define LIBTEA_PAGING_INTERNAL_H

#include <stddef.h>
#include "../libtea_config.h"
#include "libtea_ioctl.h"
#include "libtea_paging_ioctl.h"


#if LIBTEA_AARCH64
#include <linux/hugetlb.h>

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

static inline pteval_t native_pte_val(pte_t pte)
{
  return pte_val(pte);
}

static inline int pud_large(pud_t pud) {
  return pud_huge(pud);
}

static inline int pmd_large(pmd_t pmd) {
  return pmd_huge(pmd);
}
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define from_user raw_copy_from_user
#define to_user raw_copy_to_user
#else
#define from_user copy_from_user
#define to_user copy_to_user
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
unsigned long kallsyms_lookup_name(const char* name) {
  struct kprobe kp = {
    .symbol_name	= name,
  };

  int ret = register_kprobe(&kp);
  if (ret < 0) {
    return 0;
  };

  unsigned long addr = kp.addr;

  unregister_kprobe(&kp);

  return addr;
}
#endif

typedef struct {
    size_t pid;
    pgd_t *pgd;
/* Linux has 5level-fixup.h for arches which don't support 5-level paging, so safe to assume presence of P4D throughout? */
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


#endif //LIBTEA_PAGING_INTERNAL_H
