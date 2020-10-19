
/* See LICENSE file for license and copyright information */


#if defined(__linux__) || defined(LINUX) || defined(__linux)
#define LIBTEA_LINUX 1
#endif

/* Condition below will need adapting to support Windows on Arm, but MSVC is currently providing zero helpful macros */
#if defined(__i386__) || defined(__x86_64__) || LIBTEA_WINDOWS
#define LIBTEA_X86 1
#define LIBTEA_AARCH64 0
#define LIBTEA_PPC64 0

#elif defined(__aarch64__)
#define LIBTEA_X86 0
#define LIBTEA_AARCH64 1
#define LIBTEA_PPC64 0

#elif defined(__PPC64__) || defined(__ppc64__)
#define LIBTEA_X86 0
#define LIBTEA_AARCH64 0
#define LIBTEA_PPC64 1
#error "Libtea module is not yet compatible with PPC64! Aborting compilation. Please use Libtea with libtea_init_nokernel()."
#endif

/* By default, support cache and paging functionality.
 * Use KCPPFLAGS to define interrupts and enclave in
 * your Makefile if needed (as demonstrated in the root
 * directory's Makefile).
 */
#ifndef LIBTEA_SUPPORT_CACHE
#define LIBTEA_SUPPORT_CACHE 1
#endif

#ifndef LIBTEA_SUPPORT_PAGING
#define LIBTEA_SUPPORT_PAGING 1
#endif

#ifndef LIBTEA_SUPPORT_INTERRUPTS
#define LIBTEA_SUPPORT_INTERRUPTS 0
#endif

#ifndef LIBTEA_SUPPORT_ENCLAVE
#define LIBTEA_SUPPORT_ENCLAVE 0
#endif
#define LIBTEA_SUPPORT_SGX LIBTEA_SUPPORT_ENCLAVE

#include <linux/mm_types.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#endif

#ifdef CONFIG_PAGE_TABLE_ISOLATION
pgd_t __attribute__((weak)) __pti_set_user_pgtbl(pgd_t *pgdp, pgd_t pgd);
#endif

#include "../libtea_config.h"
#include "libtea_ioctl.h"
#include "libtea_internal.h"


#ifdef LIBTEA_SUPPORT_PAGING
#if LIBTEA_X86
#include "../include/arch/x86/libtea_x86_paging.h"
#elif LIBTEA_AARCH64
#include "../include/arch/aarch64/libtea_aarch64_paging.h"
#else
#include "../include/arch/ppc64/libtea_ppc64_paging.h"
#endif
#endif


#if LIBTEA_SUPPORT_SGX
  #include "linux-sgx-driver/sgx.h"
  #include <linux/sched.h>
  #include <asm/irq.h>
  #include <linux/clockchips.h>
#endif


MODULE_AUTHOR("Anon");
MODULE_DESCRIPTION("Libtea microarchitectural attack development framework driver");
MODULE_LICENSE("GPL");


typedef long (*ioctl_t)(struct file *filep, unsigned int cmd, unsigned long arg);
static bool mm_is_locked = false;
int device_busy = 0;


/* Libtea common functionality
============================================================================================*/


/* These functions *are* used by smp_call_function_single */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"


static void get_system_reg(void* ioctl_param){
  libtea_system_reg result;
  unsigned long long msr_val;
  int err;

  if(copy_from_user(&result, (libtea_system_reg*)ioctl_param, sizeof(result))){
    printk(KERN_ERR "[libtea-module]: copy_from_user failed in get_system_reg\n");
    return;
  }

  #if LIBTEA_X86
  err = rdmsrl_safe(result.reg, &msr_val);
  result.val = (size_t) msr_val;
  if(err){
    printk(KERN_ERR "[libtea-module]: rdmsrl_safe failed in get_system_reg\n");
  }

  #elif LIBTEA_AARCH64
  /* _s version avoids stringify for regs without architectural names or unsupported by GAS */
  result.val = read_sysreg_s(msr_val);

  #endif

  if(copy_to_user(ioctl_param, &result, sizeof(result))){
    printk(KERN_ERR "LIBTEA: copy_to_user failed in get_system_reg\n");
  }
}


static void set_system_reg(void* ioctl_param){

  libtea_system_reg result;
  int err;

  if(copy_from_user(&result, (libtea_system_reg*)ioctl_param, sizeof(result))){
    printk(KERN_ERR "[libtea-module]: copy_from_user failed in set_system_reg\n");
    return;
  }

  #if LIBTEA_X86
  err = wrmsrl_safe(result.reg, result.val);
  if(err){
    printk(KERN_ERR "[libtea-module]: wrmsrl_safe failed in set_system_reg\n");
  }

  #elif LIBTEA_AARCH64
  /* _s version avoids stringify for regs without architectural names or unsupported by GAS. Does not return a value. */
  write_sysreg_s(result.reg, result.val);

  #endif
}

#pragma GCC diagnostic pop  /* Start warning about unused functions again */


/* Libtea paging functionality
============================================================================================*/


#if LIBTEA_SUPPORT_PAGING

/* Hacks for umem and /dev/mem */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops umem_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
  .proc_flags = 0,
#endif
  .proc_open = NULL,
  .proc_read = NULL,
  .proc_write = NULL,
  .proc_lseek = NULL,
  .proc_release = NULL,
  .proc_poll = NULL,
  .proc_ioctl = NULL,
  .proc_mmap = NULL,
  .proc_get_unmapped_area = NULL,
};
#define OP_lseek lseek
#define OPCAT(a, b) a ## b
#define OPS(o) OPCAT(umem_ops.proc_, o)

#else
static struct file_operations umem_ops = {.owner = THIS_MODULE};
#define OP_lseek llseek
#define OPS(o) umem_ops.o
#endif

static int open_umem(struct inode *inode, struct file *filp) { return 0; }
static int has_umem = 0;

void (*flush_tlb)(unsigned long);
void (*flush_tlb_mm_range_func)(struct mm_struct*, unsigned long, unsigned long, unsigned int, bool);
static struct mm_struct* get_mm(size_t);

#if !LIBTEA_AARCH64
static const char *devmem_hook = "devmem_is_allowed";
static int devmem_bypass(struct kretprobe_instance *p, struct pt_regs *regs) {
  if (regs->ax == 0) {
    regs->ax = 1;
  }
  return 0;
}
static struct kretprobe probe_devmem = {.handler = devmem_bypass, .maxactive = 20};
#endif


static void _flush_tlb(void *addr) {

  #if LIBTEA_X86
  int pcid;
  unsigned long flags;
  unsigned long cr4;

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 98)
  #if defined(X86_FEATURE_INVPCID_SINGLE) && defined(INVPCID_TYPE_INDIV_ADDR)
  if (cpu_feature_enabled(X86_FEATURE_INVPCID_SINGLE)) {
    for(pcid = 0; pcid < 4096; pcid++) {
      invpcid_flush_one(pcid, (long unsigned int) addr);
    }
  }
  else
  #endif
  {
    raw_local_irq_save(flags);
    #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    cr4 = native_read_cr4();
    #else
    cr4 = this_cpu_read(cpu_tlbstate.cr4);
    #endif
    #else
    cr4 = __read_cr4();
    #endif
    #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    native_write_cr4(cr4 & ~X86_CR4_PGE);
    native_write_cr4(cr4);
    #else
    __write_cr4(cr4 & ~X86_CR4_PGE);
    __write_cr4(cr4);
    #endif
    raw_local_irq_restore(flags);
  }

  #else
  asm volatile ("invlpg (%0)": : "r"(addr));
  #endif

  #elif LIBTEA_AARCH64
  asm volatile ("dsb ishst");
  asm volatile ("tlbi vmalle1is");
  asm volatile ("dsb ish");
  asm volatile ("isb");
  #endif
}


static void flush_tlb_custom(unsigned long addr) {
  on_each_cpu(_flush_tlb, (void*) addr, 1);
}

static void flush_tlb_kernel(unsigned long addr) {
  flush_tlb_mm_range_func(get_mm(task_pid_nr(current)), addr, addr + PAGE_SIZE, PAGE_SHIFT, false);
}


static void _set_pat(void* _pat) {
  #if LIBTEA_X86
  int low, high;
  size_t pat = (size_t)_pat;
  low = pat & 0xffffffff;
  high = (pat >> 32) & 0xffffffff;
  asm volatile("wrmsr" : : "a"(low), "d"(high), "c"(0x277));

  #elif LIBTEA_AARCH64
  size_t pat = (size_t)_pat;
  asm volatile ("msr mair_el1, %0\n" : : "r"(pat));
  #endif
}


static void set_pat(size_t pat) {
  on_each_cpu(_set_pat, (void*) pat, 1);
}


static struct mm_struct* get_mm(size_t pid) {
  struct task_struct *task;
  struct pid* vpid;

  /* Find mm */
  task = current;
  if(pid != 0) {
    vpid = find_vpid(pid);
    if(!vpid) return NULL;
    task = pid_task(vpid, PIDTYPE_PID);
    if(!task) return NULL;
  }
  if(task->mm) {
    return task->mm;
  }
  else {
    return task->active_mm;
  }
  return NULL;
}


static int resolve_vm(size_t addr, vm_t* entry, int lock) {
  struct mm_struct *mm;

  if(!entry) return 1;
  entry->pud = NULL;
  entry->pmd = NULL;
  entry->pgd = NULL;
  entry->pte = NULL;
  entry->p4d = NULL;
  entry->valid = 0;

  mm = get_mm(entry->pid);
  if(!mm) {
    return 1;
  }

  /* Lock mm */
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_lock(mm);
  #else
  if(lock) down_read(&mm->mmap_sem);
  #endif

  /* Return PGD (page global directory) entry */
  entry->pgd = pgd_offset(mm, addr);
  if (pgd_none(*(entry->pgd)) || pgd_bad(*(entry->pgd))) {
    entry->pgd = NULL;
    goto error_out;
  }
  entry->valid |= LIBTEA_VALID_MASK_PGD;

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
  /* Return p4d offset */
  entry->p4d = p4d_offset(entry->pgd, addr);
  if (p4d_none(*(entry->p4d)) || p4d_bad(*(entry->p4d))) {
    entry->p4d = NULL;
    goto error_out;
  }
  entry->valid |= LIBTEA_VALID_MASK_P4D;

  /* Get offset of PUD (page upper directory) */
  entry->pud = pud_offset(entry->p4d, addr);
  if (pud_none(*(entry->pud))) {
    entry->pud = NULL;
    goto error_out;
  }
  entry->valid |= LIBTEA_VALID_MASK_PUD;

  #else
  /* Get offset of PUD (page upper directory) */
  entry->pud = pud_offset(entry->pgd, addr);
  if (pud_none(*(entry->pud))) {
    entry->pud = NULL;
    goto error_out;
  }
  entry->valid |= LIBTEA_VALID_MASK_PUD;
  #endif

  /* Get offset of PMD (page middle directory) */
  entry->pmd = pmd_offset(entry->pud, addr);
  if (pmd_none(*(entry->pmd)) || pud_large(*(entry->pud))) {
    entry->pmd = NULL;
    goto error_out;
  }
  entry->valid |= LIBTEA_VALID_MASK_PMD;

  /* Map PTE (page table entry) */
  entry->pte = pte_offset_map(entry->pmd, addr);
  if (entry->pte == NULL || pmd_large(*(entry->pmd))) {
    goto error_out;
  }
  entry->valid |= LIBTEA_VALID_MASK_PTE;

  /* Unmap PTE, fine on x86 and ARM64 -> unmap is NOP */
  pte_unmap(entry->pte);

  /* Unlock mm */
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_unlock(mm);
  #else
  if(lock) up_read(&mm->mmap_sem);
  #endif

  return 0;

  error_out:
    /* Unlock mm */
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    if(lock) mmap_read_unlock(mm);
    #else
    if(lock) up_read(&mm->mmap_sem);
    #endif
    return 1;
}


static int update_vm(libtea_page_entry* new_entry, int lock) {
  vm_t old_entry;
  size_t addr = new_entry->vaddr;
  struct mm_struct *mm = get_mm(new_entry->pid);
  if(!mm) return 1;

  old_entry.pid = new_entry->pid;

  /* Lock mm */
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_lock(mm);
  #else
  if(lock) down_read(&mm->mmap_sem);
  #endif

  resolve_vm(addr, &old_entry, 0);

  /* Update entries */
  if((old_entry.valid & LIBTEA_VALID_MASK_PGD) && (new_entry->valid & LIBTEA_VALID_MASK_PGD)) {
    printk(KERN_INFO "[libtea-module] Updating PGD\n");
    set_pgd(old_entry.pgd, native_make_pgd(new_entry->pgd));
  }

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
  if((old_entry.valid & LIBTEA_VALID_MASK_P4D) && (new_entry->valid & LIBTEA_VALID_MASK_P4D)) {
    printk(KERN_INFO "[libtea-module] Updating P4D\n");
    set_p4d(old_entry.p4d, native_make_p4d(new_entry->p4d));
  }
  #endif

  if((old_entry.valid & LIBTEA_VALID_MASK_PMD) && (new_entry->valid & LIBTEA_VALID_MASK_PMD)) {
    printk(KERN_INFO "[libtea-module] Updating PMD\n");
    set_pmd(old_entry.pmd, native_make_pmd(new_entry->pmd));
  }

  if((old_entry.valid & LIBTEA_VALID_MASK_PUD) && (new_entry->valid & LIBTEA_VALID_MASK_PUD)) {
    printk(KERN_INFO "[libtea-module] Updating PUD\n");
    set_pud(old_entry.pud, native_make_pud(new_entry->pud));
  }

  if((old_entry.valid & LIBTEA_VALID_MASK_PTE) && (new_entry->valid & LIBTEA_VALID_MASK_PTE)) {
    printk(KERN_INFO "[libtea-module] Updating PTE\n");
    set_pte(old_entry.pte, native_make_pte(new_entry->pte));
  }

  flush_tlb(addr);

  /* Unlock mm */
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  if(lock) mmap_read_unlock(mm);
  #else
  if(lock) up_read(&mm->mmap_sem);
  #endif

  return 0;
}


static void vm_to_user(libtea_page_entry* user, vm_t* vm) {
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
  #if CONFIG_PGTABLE_LEVELS > 4
  if(vm->p4d) user->p4d = (vm->p4d)->p4d;
  #else
  #if !defined(__ARCH_HAS_5LEVEL_HACK)
  if(vm->p4d) user->p4d = (vm->p4d)->pgd.pgd;
  #else
  if(vm->p4d) user->p4d = (vm->p4d)->pgd;
  #endif
  #endif
  #endif

  #if LIBTEA_X86
  if(vm->pgd) user->pgd = (vm->pgd)->pgd;
  if(vm->pmd) user->pmd = (vm->pmd)->pmd;
  if(vm->pud) user->pud = (vm->pud)->pud;
  if(vm->pte) user->pte = (vm->pte)->pte;

  #elif LIBTEA_AARCH64
  if(vm->pgd) user->pgd = pgd_val(*(vm->pgd));
  if(vm->pmd) user->pmd = pmd_val(*(vm->pmd));
  if(vm->pud) user->pud = pud_val(*(vm->pud));
  if(vm->pte) user->pte = pte_val(*(vm->pte));
  #endif

  user->valid = vm->valid;
}


#endif //LIBTEA_SUPPORT_PAGING


#if LIBTEA_SUPPORT_SGX
long libtea_ioctl_enclave_info(struct file *filep, unsigned int cmd, unsigned long arg){
  struct sgx_encl *enclave;
  struct vm_area_struct *vma = NULL;
  struct libtea_enclave_info *info = (struct libtea_enclave_info *) arg;
  vma = find_vma(current->mm, (uint64_t) info->tcs);
  enclave = vma->vm_private_data;
  RET_ASSERT(vma && enclave);
  RET_ASSERT(info->aep && info->tcs);
  info->base = enclave->base;
  info->size = enclave->size;
  return 0;
}

typedef long (*apvm_t)(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);

long edbgrdwr(unsigned long addr, void *buf, int len, int write){
  apvm_t apvm;

  /* access_process_vm will use the vm_operations defined by the isgx driver */
  RET_ASSERT(apvm = (apvm_t) kallsyms_lookup_name("access_process_vm"));
  return apvm(current, addr, buf, len, write);
}


long libtea_ioctl_edbgrd(struct file *filep, unsigned int cmd, unsigned long arg){
  libtea_edbgrd* data = (libtea_edbgrd*) arg;
  uint8_t buf[data->len];
  if (data->write && copy_from_user(buf, (void __user *) data->val, data->len)){
    printk(KERN_INFO "[libtea-module]: copy_from_user failed in libtea_ioctl_edbgrd\n");
    return -EFAULT;
  }

  edbgrdwr((unsigned long) data->adrs, &buf, data->len, data->write);

  if (!data->write && copy_to_user((void __user *) data->val, buf, data->len)){
    printk(KERN_INFO "[libtea-module]: copy_to_user failed in libtea_ioctl_edbgrd\n");
    return -EFAULT;
  }

  return 0;
}

#endif


static long libtea_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {

  char data[256];
  ioctl_t handler = NULL;
  long ret;

  switch (ioctl_num) {

    case LIBTEA_IOCTL_SET_SYSTEM_REG:
    {
      libtea_system_reg reg;
      (void)from_user(&reg, (libtea_system_reg*)ioctl_param, sizeof(reg));
      /* Ensure we modify the system register on the correct CPU */
      smp_call_function_single(reg.cpu, (smp_call_func_t) set_system_reg, (void*) ioctl_param, 0);
      return 0;
    }
    case LIBTEA_IOCTL_GET_SYSTEM_REG:
    {
      libtea_system_reg reg;
      (void)from_user(&reg, (libtea_system_reg*)ioctl_param, sizeof(reg));
      /* Ensure we modify the system register on the correct CPU */
      smp_call_function_single(reg.cpu, (smp_call_func_t) get_system_reg, (void*) ioctl_param, 0);
      return 0;
    }
    case LIBTEA_IOCTL_GET_KERNEL_PHYS_ADDR:
    {
       void* vaddr;
       phys_addr_t paddr;
       (void)from_user(&vaddr, (void*)ioctl_param, sizeof(vaddr));
       paddr = virt_to_phys(vaddr);
       (void)to_user((void*)ioctl_param, &paddr, sizeof(paddr));
       return 0;
    }

    #if LIBTEA_SUPPORT_PAGING
    case LIBTEA_IOCTL_VM_RESOLVE:
    {
      libtea_page_entry vm_user;
      vm_t vm;
      (void)from_user(&vm_user, (void*)ioctl_param, sizeof(vm_user));
      vm.pid = vm_user.pid;
      resolve_vm(vm_user.vaddr, &vm, !mm_is_locked);
      vm_to_user(&vm_user, &vm);
      (void)to_user((void*)ioctl_param, &vm_user, sizeof(vm_user));
      return 0;
    }
    case LIBTEA_IOCTL_VM_UPDATE:
    {
      libtea_page_entry vm_user;
      (void)from_user(&vm_user, (void*)ioctl_param, sizeof(vm_user));
      update_vm(&vm_user, !mm_is_locked);
      return 0;
    }
    case LIBTEA_IOCTL_VM_LOCK:
    {
      struct mm_struct *mm = current->active_mm;
      if(mm_is_locked) {
        printk(KERN_INFO "[libtea-module] VM is already locked\n");
        return -1;
      }
      #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
      mmap_read_lock(mm);
      #else
      down_read(&mm->mmap_sem);
      #endif
      mm_is_locked = true;
      return 0;
    }
    case LIBTEA_IOCTL_VM_UNLOCK:
    {
      struct mm_struct *mm = current->active_mm;
      if(!mm_is_locked) {
        printk(KERN_INFO "[libtea-module] VM is not locked\n");
        return -1;
      }
      #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
      mmap_read_unlock(mm);
      #else
      up_read(&mm->mmap_sem);
      #endif
      mm_is_locked = false;
      return 0;
    }
    case LIBTEA_IOCTL_READ_PAGE:
    {
      libtea_physical_page page;
      (void)from_user(&page, (void*)ioctl_param, sizeof(page));
      to_user(page.buffer, phys_to_virt(page.pfn * PAGE_SIZE), PAGE_SIZE);
      return 0;
    }
    case LIBTEA_IOCTL_WRITE_PAGE:
    {
      libtea_physical_page page;
      (void)from_user(&page, (void*)ioctl_param, sizeof(page));
      (void)from_user(phys_to_virt(page.pfn * PAGE_SIZE), page.buffer, PAGE_SIZE);
      return 0;
    }
    case LIBTEA_IOCTL_GET_ROOT:
    {
      struct mm_struct *mm;
      libtea_paging_root paging;

      (void)from_user(&paging, (void*)ioctl_param, sizeof(paging));
      mm = get_mm(paging.pid);
      if(!mm) return 1;
      #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
      if(!mm_is_locked) mmap_read_lock(mm);
      #else
      if(!mm_is_locked) down_read(&mm->mmap_sem);
      #endif
      paging.root = virt_to_phys(mm->pgd);
      #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
      if(!mm_is_locked) mmap_read_unlock(mm);
      #else
      if(!mm_is_locked) up_read(&mm->mmap_sem);
      #endif
      (void)to_user((void*)ioctl_param, &paging, sizeof(paging));
      return 0;
    }
    case LIBTEA_IOCTL_SET_ROOT:
    {
      struct mm_struct *mm;
      libtea_paging_root paging = {0};

      (void)from_user(&paging, (void*)ioctl_param, sizeof(paging));
      mm = get_mm(paging.pid);
      if(!mm) return 1;
      #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
      if(!mm_is_locked) mmap_read_lock(mm);
      #else
      if(!mm_is_locked) down_read(&mm->mmap_sem);
      #endif
      mm->pgd = (pgd_t*)phys_to_virt(paging.root);
      #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
      if(!mm_is_locked) mmap_read_unlock(mm);
      #else
      if(!mm_is_locked) up_read(&mm->mmap_sem);
      #endif
      return 0;
    }
    case LIBTEA_IOCTL_GET_PAGESIZE:
      return PAGE_SIZE;
    case LIBTEA_IOCTL_FLUSH_TLB:
      flush_tlb(ioctl_param);
      return 0;
    case LIBTEA_IOCTL_GET_PAT:
    {
      #if LIBTEA_X86
      int low, high;
      size_t pat;
      asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(0x277));
      pat = low | (((size_t)high) << 32);
      (void)to_user((void*)ioctl_param, &pat, sizeof(pat));
      return 0;

      #elif LIBTEA_ARM
      uint64_t value;
      asm volatile ("mrs %0, mair_el1\n" : "=r"(value));
      (void)to_user((void*)ioctl_param, &value, sizeof(value));
      return 0;
      #endif
    }
    case LIBTEA_IOCTL_SET_PAT:
    {
      set_pat(ioctl_param);
      return 0;
    }
    case LIBTEA_IOCTL_SWITCH_FLUSH_TLB_IMPLEMENTATION:
    {
      if((int)ioctl_param != LIBTEA_FLUSH_TLB_KERNEL && (int) ioctl_param != LIBTEA_FLUSH_TLB_CUSTOM){
        return -1;
      }
      else {
        flush_tlb = ((int)ioctl_param == LIBTEA_FLUSH_TLB_KERNEL) ? flush_tlb_kernel : flush_tlb_custom;
        return 0;
      }
    }
    #endif //LIBTEA_SUPPORT_PAGING

    #if LIBTEA_SUPPORT_SGX
    case LIBTEA_IOCTL_ENCLAVE_INFO:
    {
      handler = libtea_ioctl_enclave_info;
      RET_ASSERT(handler && (_IOC_SIZE(ioctl_num) < 256));
      if (copy_from_user(data, (void __user *) ioctl_param, _IOC_SIZE(ioctl_num))){
        printk(KERN_INFO "[libtea-module]: copy_from_user failed in LIBTEA_IOCTL_ENCLAVE_INFO\n");
        return -EFAULT;
      }
      ret = handler(file, ioctl_num, (unsigned long) ((void *) data));
      if (!ret && (ioctl_num & IOC_OUT)) {
        if (copy_to_user((void __user *) ioctl_param, data, _IOC_SIZE(ioctl_num))){
          printk(KERN_INFO "[libtea-module]: copy_to_user failed in LIBTEA_IOCTL_ENCLAVE_INFO\n");
          return -EFAULT;
        }
      }
      return 0;
    }
    case LIBTEA_IOCTL_EDBGRD:
    {
      handler = libtea_ioctl_edbgrd;
      RET_ASSERT(handler && (_IOC_SIZE(ioctl_num) < 256));
      if (copy_from_user(data, (void __user *) ioctl_param, _IOC_SIZE(ioctl_num))){
        printk(KERN_INFO "[libtea-module]: copy_from_user failed in LIBTEA_IOCTL_EDBGRD\n");
        return -EFAULT;
      }
      ret = handler(file, ioctl_num, (unsigned long) ((void *) data));
      if (!ret && (ioctl_num & IOC_OUT)) {
        if (copy_to_user((void __user *) ioctl_param, data, _IOC_SIZE(ioctl_num))){
          printk(KERN_INFO "[libtea-module]: copy_to_user failed in LIBTEA_IOCTL_EDBGRD\n");
          return -EFAULT;
        }
      }
      return 0;
    }
    #endif

    default:
      return -1;
  }

  return 0;
}


static int libtea_open(struct inode *inode, struct file *file) {
  /* Check if device is busy */
  if (device_busy) {
    printk(KERN_ALERT "[libtea-module] Failed opening device, device is busy\n");
    return -EBUSY;
  }

  /* Lock device */
  device_busy = 1;
  return 0;
}


static int libtea_release(struct inode *inode, struct file *file) {
  /* Unlock device */
  device_busy = 0;
  return 0;
}


static struct file_operations libtea_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = libtea_ioctl,
  .open = libtea_open,
  .release = libtea_release
};


static struct miscdevice libtea_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = LIBTEA_DEVICE_NAME,
  .fops = &libtea_fops,
  .mode = S_IRWXUGO
};


int init_module(void) {
  int r;

  /* Register device */
  r = misc_register(&libtea_dev);
  if (r != 0) {
    printk(KERN_ALERT "[libtea-module] Failed registering device with %d\n", r);
    libtea_dev.this_device = NULL;
    return -EINVAL;
  }

  #if LIBTEA_SUPPORT_PAGING

  flush_tlb_mm_range_func = (void *) kallsyms_lookup_name("flush_tlb_mm_range");
  if(!flush_tlb_mm_range_func) {
    printk(KERN_ALERT "[libtea-module] Could not retrieve flush_tlb_mm_range function! TLB flushing with the kernel implementation will fail.\n");
  }
  flush_tlb = flush_tlb_kernel;

  #if !LIBTEA_AARCH64
  probe_devmem.kp.symbol_name = devmem_hook;

  if (register_kretprobe(&probe_devmem) < 0) {
    printk(KERN_ALERT "[libtea-module] Could not bypass /dev/mem restriction\n");
    misc_deregister(&libtea_dev);
    return -EINVAL;
  }
  else {
    printk(KERN_INFO "[libtea-module] /dev/mem is now superuser read-/writable\n");
  }
  #endif

  OPS(OP_lseek) = (void*)kallsyms_lookup_name("memory_lseek");
  OPS(read) = (void*)kallsyms_lookup_name("read_mem");
  OPS(write) = (void*)kallsyms_lookup_name("write_mem");
  OPS(mmap) = (void*)kallsyms_lookup_name("mmap_mem");
  OPS(open) = open_umem;

  if (!OPS(OP_lseek) || !OPS(read) || !OPS(write) || !OPS(mmap) || !OPS(open)) {
    printk(KERN_ALERT "[libtea-module] Could not create unprivileged memory access\n");
  }
  else {
    //Even if this is set to 0777 instead, you still can't mmap it PROT_EXEC, so have to use /dev/mem instead for GDT and IDT mappings?
    proc_create("libtea_umem", 0666, NULL, &umem_ops);
    printk(KERN_INFO "[libtea-module] Unprivileged memory access via /proc/libtea_umem set up\n");
    has_umem = 1;
  }

  #endif //LIBTEA_SUPPORT_PAGING

  printk(KERN_INFO "[libtea-module] Loaded.\n");

  return 0;
}


void cleanup_module(void) {
  misc_deregister(&libtea_dev);

  #if LIBTEA_SUPPORT_PAGING

  #if !LIBTEA_AARCH64
  unregister_kretprobe(&probe_devmem);
  #endif

  if (has_umem) {
    printk(KERN_INFO "[libtea-module] Removing unprivileged memory access\n");
    remove_proc_entry("libtea_umem", NULL);
  }

  #endif //LIBTEA_SUPPORT_PAGING

  printk(KERN_INFO "[libtea-module] Removed.\n");
}
