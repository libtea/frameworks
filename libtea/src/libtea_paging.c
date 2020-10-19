
/* See LICENSE file for license and copyright information */

/* Start libtea_paging.c */
//---------------------------------------------------------------------------

#include <string.h>
#include "libtea_paging.h"
#include "libtea_arch_paging.h"
#include "libtea_paging_ioctl.h"


typedef size_t(*libtea_phys_read)(libtea_instance*, size_t);
typedef void(*libtea_phys_write)(libtea_instance*, size_t, size_t);


/* Internal functions not part of public API */

libtea_page_entry libtea__resolve_addr_kernel(libtea_instance* instance, void* address, pid_t pid);
static libtea_page_entry libtea__resolve_addr_user_ext(libtea_instance* instance, void* address, pid_t pid, libtea_phys_read deref);
static libtea_page_entry libtea__resolve_addr_user(libtea_instance* instance, void* address, pid_t pid);
#if LIBTEA_LINUX
static libtea_page_entry libtea__resolve_addr_user_map(libtea_instance* instance, void* address, pid_t pid);
#endif
void libtea__update_addr_kernel(libtea_instance* instance, void* address, pid_t pid, libtea_page_entry* vm);
void libtea__update_addr_user_ext(libtea_instance* instance, void* address, pid_t pid, libtea_page_entry* vm, libtea_phys_write pset);
static void libtea__update_addr_user(libtea_instance* instance, void* address, pid_t pid, libtea_page_entry* vm);
#if LIBTEA_LINUX
static void libtea__update_addr_user_map(libtea_instance* instance, void* address, pid_t pid, libtea_page_entry* vm);
#endif
uint64_t libtea__get_physical_base_address(libtea_page_entry entry, libtea_page_level level);
uint64_t libtea__get_virtual_address_index(libtea_page_entry entry, libtea_page_level level);


static inline size_t libtea__phys_read_map(libtea_instance* instance, size_t address) {
  return *(size_t*)(instance->vmem + address);
}


static inline void libtea__phys_write_map(libtea_instance* instance, size_t address, size_t value) {
  *(size_t*)(instance->vmem + address) = value;
}


static inline size_t libtea__phys_read_pread(libtea_instance* instance, size_t address) {
  size_t val = 0;

  #if LIBTEA_LINUX
  pread(instance->umem_fd, &val, sizeof(size_t), address);

  #else
  ULONG returnLength;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_READ_PHYS_VAL, (LPVOID)&address, sizeof(address), (LPVOID)&val, sizeof(val), &returnLength, 0);
  #endif

  return val;
}


static inline void libtea__phys_write_pwrite(libtea_instance* instance, size_t address, size_t value) {

  #if LIBTEA_LINUX
  pwrite(instance->umem_fd, &value, sizeof(size_t), address);

  #else
  ULONG returnLength;
  size_t info[2];
  info[0] = address;
  info[1] = value;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_WRITE_PHYS_VAL, (LPVOID)&info, sizeof(info), (LPVOID)&info, sizeof(info), &returnLength, 0);
  #endif

}


libtea_page_entry libtea__resolve_addr_kernel(libtea_instance* instance, void* address, pid_t pid) {
  libtea_page_entry vm;
  vm.vaddr = (size_t)address;
  vm.pid = (size_t)pid;

  #if LIBTEA_LINUX
  ioctl(instance->module_fd, LIBTEA_IOCTL_VM_RESOLVE, (size_t)&vm);

  #else
  NO_WINDOWS_SUPPORT;
  #endif

  return vm;
}


static libtea_page_entry libtea__resolve_addr_user_ext(libtea_instance* instance, void* address, pid_t pid, libtea_phys_read deref) {
  size_t root = (pid == 0) ? instance->paging_root : libtea_get_paging_root(instance, pid);

  int pgdi, p4di, pudi, pmdi, pti;
  size_t addr = (size_t)address;
  pgdi = (addr >> (instance->paging_definition.page_offset
        + instance->paging_definition.pt_entries
        + instance->paging_definition.pmd_entries
        + instance->paging_definition.pud_entries
        + instance->paging_definition.p4d_entries)) % (1ull << instance->paging_definition.pgd_entries);
  p4di = (addr >> (instance->paging_definition.page_offset
        + instance->paging_definition.pt_entries
        + instance->paging_definition.pmd_entries
        + instance->paging_definition.pud_entries)) % (1ull << instance->paging_definition.p4d_entries);
  pudi = (addr >> (instance->paging_definition.page_offset
        + instance->paging_definition.pt_entries
        + instance->paging_definition.pmd_entries)) % (1ull << instance->paging_definition.pud_entries);
  pmdi = (addr >> (instance->paging_definition.page_offset
        + instance->paging_definition.pt_entries)) % (1ull << instance->paging_definition.pmd_entries);
  pti = (addr >> instance->paging_definition.page_offset) % (1ull << instance->paging_definition.pt_entries);

  libtea_page_entry resolved;
  memset(&resolved, 0, sizeof(resolved));
  resolved.vaddr = (size_t)address;
  resolved.pid = (size_t)pid;
  resolved.valid = 0;

  if(!root) return resolved;

  size_t pgd_entry, p4d_entry, pud_entry, pmd_entry, pt_entry;

  pgd_entry = deref(instance, root + pgdi * sizeof(size_t));
  if (libtea_cast(pgd_entry, libtea_pgd).present != LIBTEA_PAGE_PRESENT) {
    return resolved;
  }
  resolved.pgd = pgd_entry;
  resolved.valid |= LIBTEA_VALID_MASK_PGD;
  if (instance->paging_definition.has_p4d) {
    size_t pfn = (size_t)(libtea_cast(pgd_entry, libtea_pgd).pfn);
    p4d_entry = deref(instance, pfn * instance->pagesize + p4di * sizeof(size_t));
    resolved.valid |= LIBTEA_VALID_MASK_P4D;
  }
  else {
    p4d_entry = pgd_entry;
  }
  resolved.p4d = p4d_entry;

  if (libtea_cast(p4d_entry, libtea_p4d).present != LIBTEA_PAGE_PRESENT) {
    return resolved;
  }

  if (instance->paging_definition.has_pud) {
    size_t pfn = (size_t)(libtea_cast(p4d_entry, libtea_p4d).pfn);
    pud_entry = deref(instance, pfn * instance->pagesize + pudi * sizeof(size_t));
    resolved.valid |= LIBTEA_VALID_MASK_PUD;
  }
  else {
    pud_entry = p4d_entry;
  }
  resolved.pud = pud_entry;

  if (libtea_cast(pud_entry, libtea_pud).present != LIBTEA_PAGE_PRESENT) {
    return resolved;
  }

  if (instance->paging_definition.has_pmd) {
    size_t pfn = (size_t)(libtea_cast(pud_entry, libtea_pud).pfn);
    pmd_entry = deref(instance, pfn * instance->pagesize + pmdi * sizeof(size_t));
    resolved.valid |= LIBTEA_VALID_MASK_PMD;
  }
  else {
    pmd_entry = pud_entry;
  }
  resolved.pmd = pmd_entry;

  if (libtea_cast(pmd_entry, libtea_pmd).present != LIBTEA_PAGE_PRESENT) {
    return resolved;
  }

  #if LIBTEA_X86
    if (!libtea_cast(pmd_entry, libtea_pmd).size) {
  #endif

    /* Normal 4KB page */
    size_t pfn = (size_t)(libtea_cast(pmd_entry, libtea_pmd).pfn);
    pt_entry = deref(instance, pfn * instance->pagesize + pti * sizeof(size_t));
    resolved.pte = pt_entry;
    resolved.valid |= LIBTEA_VALID_MASK_PTE;
    if (libtea_cast(pt_entry, libtea_pte).present != LIBTEA_PAGE_PRESENT) {
      return resolved;
    }
  #if LIBTEA_X86
  }
  #endif

  return resolved;
}


static libtea_page_entry libtea__resolve_addr_user(libtea_instance* instance, void* address, pid_t pid) {
  return libtea__resolve_addr_user_ext(instance, address, pid, libtea__phys_read_pread);
}


#if LIBTEA_LINUX
static libtea_page_entry libtea__resolve_addr_user_map(libtea_instance* instance, void* address, pid_t pid) {
  return libtea__resolve_addr_user_ext(instance, address, pid, libtea__phys_read_map);
}
#endif


void libtea__update_addr_kernel(libtea_instance* instance, void* address, pid_t pid, libtea_page_entry* vm) {
  vm->vaddr = (size_t)address;
  vm->pid = (size_t)pid;

  #if LIBTEA_LINUX
  ioctl(instance->module_fd, LIBTEA_IOCTL_VM_UPDATE, (size_t)vm);

  #else
  NO_WINDOWS_SUPPORT;
  #endif

}


void libtea__update_addr_user_ext(libtea_instance* instance, void* address, pid_t pid, libtea_page_entry* vm, libtea_phys_write pset) {
  libtea_page_entry current = libtea_resolve_addr(instance, address, pid);
  size_t root = (pid == 0) ? instance->paging_root : libtea_get_paging_root(instance, pid);

  if(!root) return;

  size_t pgdi, p4di, pudi, pmdi, pti;
  size_t addr = (size_t)address;
  pgdi = (addr >> (instance->paging_definition.page_offset
       + instance->paging_definition.pt_entries
       + instance->paging_definition.pmd_entries
       + instance->paging_definition.pud_entries
       + instance->paging_definition.p4d_entries)) % (1ull << instance->paging_definition.pgd_entries);
  p4di = (addr >> (instance->paging_definition.page_offset
       + instance->paging_definition.pt_entries
       + instance->paging_definition.pmd_entries
       + instance->paging_definition.pud_entries)) % (1ull << instance->paging_definition.p4d_entries);
  pudi = (addr >> (instance->paging_definition.page_offset
       + instance->paging_definition.pt_entries
       + instance->paging_definition.pmd_entries)) % (1ull << instance->paging_definition.pud_entries);
  pmdi = (addr >> (instance->paging_definition.page_offset
       + instance->paging_definition.pt_entries)) % (1ull << instance->paging_definition.pmd_entries);
  pti = (addr >> instance->paging_definition.page_offset) % (1ull << instance->paging_definition.pt_entries);

  if ((vm->valid & LIBTEA_VALID_MASK_PTE) && (current.valid & LIBTEA_VALID_MASK_PTE)) {
    pset(instance, (size_t)libtea_cast(current.pmd, libtea_pmd).pfn * instance->pagesize + pti * (instance->pagesize / (1 << instance->paging_definition.pt_entries)), vm->pte);
  }
  if ((vm->valid & LIBTEA_VALID_MASK_PMD) && (current.valid & LIBTEA_VALID_MASK_PMD) && instance->paging_definition.has_pmd) {
    pset(instance, (size_t)libtea_cast(current.pud, libtea_pud).pfn * instance->pagesize + pmdi * (instance->pagesize / (1 << instance->paging_definition.pmd_entries)), vm->pmd);
  }
  if ((vm->valid & LIBTEA_VALID_MASK_PUD) && (current.valid & LIBTEA_VALID_MASK_PUD) && instance->paging_definition.has_pud) {
    pset(instance, (size_t)libtea_cast(current.p4d, libtea_p4d).pfn * instance->pagesize + pudi * (instance->pagesize / (1 << instance->paging_definition.pud_entries)), vm->pud);
  }
  if ((vm->valid & LIBTEA_VALID_MASK_P4D) && (current.valid & LIBTEA_VALID_MASK_P4D) && instance->paging_definition.has_p4d) {
    pset(instance, (size_t)libtea_cast(current.pgd, libtea_pgd).pfn * instance->pagesize + p4di * (instance->pagesize / (1 << instance->paging_definition.p4d_entries)), vm->p4d);
  }
  if ((vm->valid & LIBTEA_VALID_MASK_PGD) && (current.valid & LIBTEA_VALID_MASK_PGD) && instance->paging_definition.has_pgd) {
    pset(instance, root + pgdi * (instance->pagesize / (1 << instance->paging_definition.pgd_entries)), vm->pgd);
  }

  libtea_flush_tlb(instance, address);
}


static void libtea__update_addr_user(libtea_instance* instance, void* address, pid_t pid, libtea_page_entry* vm) {
  libtea__update_addr_user_ext(instance, address, pid, vm, libtea__phys_write_pwrite);
  libtea_flush_tlb(instance, address);
}


#if LIBTEA_LINUX
static void libtea__update_addr_user_map(libtea_instance* instance, void* address, pid_t pid, libtea_page_entry* vm) {
  libtea__update_addr_user_ext(instance, address, pid, vm, libtea__phys_write_map);
  libtea_flush_tlb(instance, address);
}
#endif


uint64_t libtea__get_physical_base_address(libtea_page_entry entry, libtea_page_level level){
  return libtea__arch_get_physical_base_address(entry, level);
}


uint64_t libtea__get_virtual_address_index(libtea_page_entry entry, libtea_page_level level){
  return libtea__arch_get_virtual_address_index(entry, level);
}


#define LIBTEA_B(val, bit) (!!((val) & (1ull << (bit))))


int libtea__paging_init(libtea_instance* instance) {

  #if LIBTEA_LINUX
  libtea_set_paging_implementation(instance, LIBTEA_PAGING_IMPL_KERNEL);
  #else
  libtea_set_paging_implementation(instance, LIBTEA_PAGING_IMPL_USER_PREAD);
  #endif

  instance->pagesize = libtea_get_pagesize(instance);
  #if LIBTEA_AARCH64
  if(instance->pagesize == 4096*4){
    libtea_page_shift = 14;
  }
  else if(instance->pagesize == 4096*16){
    libtea_page_shift = 16;
  }
  #endif

  libtea__arch_get_paging_definitions(instance);
  return 0;
}


void libtea__cleanup_paging(libtea_instance* instance) {
  #if LIBTEA_LINUX
  if(instance->umem_fd > 0) close(instance->umem_fd);
  if(instance->mem_fd > 0) close(instance->mem_fd);
  #endif
}


/* Public API (plus libtea_update_addr and libtea_resolve_addr versions) */


void libtea_set_paging_implementation(libtea_instance* instance, int implementation) {
  if (implementation == LIBTEA_PAGING_IMPL_KERNEL) {

    #if LIBTEA_LINUX
    libtea_resolve_addr = libtea__resolve_addr_kernel;
    libtea_update_addr = libtea__update_addr_kernel;

    #else
    libtea_info("Error: Libtea kernel paging implementation not supported on Windows.");
    #endif

  }
  else if (implementation == LIBTEA_PAGING_IMPL_USER_PREAD) {
    libtea_resolve_addr = libtea__resolve_addr_user;
    libtea_update_addr = libtea__update_addr_user;
    instance->paging_root = libtea_get_paging_root(instance, 0);
  }
  else if (implementation == LIBTEA_PAGING_IMPL_USER) {

    #if LIBTEA_LINUX
    libtea_resolve_addr = libtea__resolve_addr_user_map;
    libtea_update_addr = libtea__update_addr_user_map;
    instance->paging_root = libtea_get_paging_root(instance, 0);
    if (!instance->vmem) {
      instance->vmem = (unsigned char*)mmap(NULL, 32ull << 30ull, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_NORESERVE, instance->umem_fd, 0);
      libtea_info("Mapped physical memory to %p.", instance->vmem);
    }

    #else
    libtea_info("Error: Libtea user paging implementation not supported on Windows.");
    #endif

  }
  else {
    libtea_info("Error: invalid Libtea paging implementation.");
  }
}


void libtea_set_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit) {
  libtea_page_entry vm = libtea_resolve_addr(instance, address, pid);
  if (!(vm.valid & LIBTEA_VALID_MASK_PTE)) return;
  vm.pte |= (1ull << bit);
  vm.valid = LIBTEA_VALID_MASK_PTE;
  libtea_update_addr(instance, address, pid, &vm);
}


void libtea_clear_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit) {
  libtea_page_entry vm = libtea_resolve_addr(instance, address, pid);
  if (!(vm.valid & LIBTEA_VALID_MASK_PTE)) return;
  vm.pte &= ~(1ull << bit);
  vm.valid = LIBTEA_VALID_MASK_PTE;
  libtea_update_addr(instance, address, pid, &vm);
}


int libtea_mark_page_present(libtea_instance* instance, void* page, int prot) {
  #if LIBTEA_LINUX && LIBTEA_X86
  libtea_page_entry vm = libtea_resolve_addr(instance, page, 0);
  vm.pte |= ~(1ull << LIBTEA_PAGE_BIT_PRESENT);
  vm.valid = LIBTEA_VALID_MASK_PTE;
  //Must use mprotect so Linux is aware we unmapped the page (then restore unmitigated PTE) - otherwise system will crash
  if(mprotect((void*) (((uint64_t) page) & ~LIBTEA_PFN_MASK), 4096, prot) != 0) {
    return LIBTEA_ERROR;
  }
  libtea_update_addr(instance, page, 0, &vm);
  return LIBTEA_SUCCESS;
  #elif LIBTEA_LINUX
  libtea_info("libtea_mark_page_present is only supported on x86!");
  return LIBTEA_ERROR;
  #else
  NO_WINDOWS_SUPPORT;
  return LIBTEA_ERROR;
  #endif
}


int libtea_mark_page_not_present(libtea_instance* instance, void* page) {
  #if LIBTEA_LINUX && LIBTEA_X86
  libtea_page_entry vm = libtea_resolve_addr(instance, page, 0);
  vm.pte &= ~(1ull << LIBTEA_PAGE_BIT_PRESENT);
  vm.valid = LIBTEA_VALID_MASK_PTE;
  //Must use mprotect so Linux is aware we unmapped the page (then restore unmitigated PTE) - otherwise system will crash
  if(mprotect((void*) (((uint64_t) page) & ~LIBTEA_PFN_MASK), 4096, PROT_NONE) != 0) {
    return LIBTEA_ERROR;
  }
  libtea_update_addr(instance, page, 0, &vm);
  return LIBTEA_SUCCESS;
  #elif LIBTEA_LINUX
  libtea_info("libtea_mark_page_not_present is only supported on x86!");
  return LIBTEA_ERROR;
  #else
  NO_WINDOWS_SUPPORT;
  return LIBTEA_ERROR;
  #endif
}


unsigned char libtea_get_addr_page_bit(libtea_instance* instance, void* address, pid_t pid, int bit) {
  libtea_page_entry vm = libtea_resolve_addr(instance, address, pid);
  return !!(vm.pte & (1ull << bit));
}


size_t libtea_get_addr_pfn(libtea_instance* instance, void* address, pid_t pid) {
  libtea_page_entry vm = libtea_resolve_addr(instance, address, pid);
  if (!(vm.valid & LIBTEA_VALID_MASK_PTE)) return 0;
  else return libtea_get_pfn(vm.pte);
}


void libtea_set_addr_pfn(libtea_instance* instance, void* address, pid_t pid, size_t pfn) {
  libtea_page_entry vm = libtea_resolve_addr(instance, address, pid);
  if (!(vm.valid & LIBTEA_VALID_MASK_PTE)) return;
  vm.pte = libtea_set_pfn(vm.pte, pfn);
  vm.valid = LIBTEA_VALID_MASK_PTE;
  libtea_update_addr(instance, address, pid, &vm);
}


int libtea_get_pagesize(libtea_instance* instance) {

  #if LIBTEA_LINUX
  return getpagesize();

  #else
  SYSTEM_INFO sysinfo;
  GetSystemInfo(&sysinfo);
  return sysinfo.dwPageSize;
  #endif

}


size_t libtea_set_pfn(size_t pte, size_t pfn) {
  pte &= libtea__arch_set_pfn();
  pte |= pfn << 12;
  return pte;
}


size_t libtea_get_pfn(size_t pte) {
  return libtea__arch_get_pfn(pte);
}


void libtea_read_physical_page(libtea_instance* instance, size_t pfn, char* buffer) {
  #if LIBTEA_LINUX
  if (instance->umem_fd > 0) {
    pread(instance->umem_fd, buffer, instance->pagesize, pfn * instance->pagesize);
  }
  else {
    libtea_physical_page page;
    page.buffer = (unsigned char*)buffer;
    page.pfn = pfn;
    ioctl(instance->module_fd, LIBTEA_IOCTL_READ_PAGE, (size_t)&page);
  }
  #else
  DWORD returnLength;
  pfn *= instance->pagesize;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_READ_PAGE, (LPVOID)&pfn, sizeof(pfn), (LPVOID)buffer, 4096, &returnLength, 0);
  #endif
}


void libtea_write_physical_page(libtea_instance* instance, size_t pfn, char* content) {
  #if LIBTEA_LINUX
  if (instance->umem_fd > 0) {
    pwrite(instance->umem_fd, content, instance->pagesize, pfn * instance->pagesize);
  }
  else {
    libtea_physical_page page;
    page.buffer = (unsigned char*)content;
    page.pfn = pfn;
    ioctl(instance->module_fd, LIBTEA_IOCTL_WRITE_PAGE, (size_t)&page);
  }
  #else
  DWORD returnLength;
  libtea_physical_page page;
  if (instance->pagesize != 4096) {
    libtea_info("Error: page sizes other than 4096 not supported for Libtea paging on Windows.");
    return;
  }
  page.paddr = pfn * instance->pagesize;
  memcpy(page.content, content, instance->pagesize);
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_WRITE_PAGE, (LPVOID)&page, sizeof(libtea_physical_page), (LPVOID)&page, sizeof(libtea_physical_page), &returnLength, 0);
  #endif
}


void* libtea_map_physical_address_range(libtea_instance* instance, size_t paddr, size_t length, int prot, bool use_dev_mem) {

  #if LIBTEA_LINUX
  size_t pfn = (paddr & ~LIBTEA_PFN_MASK);
  //TODO query PAT errors when trying to switch to LIBTEA_PAGING_IMPL_USER
  int fd = use_dev_mem ? instance->mem_fd : instance->umem_fd;

  char* map = (char*) mmap(0, length, prot, MAP_SHARED, fd, pfn);
  if (map == MAP_FAILED) {
    libtea_info("Error in libtea_map_physical_address_range, mmap errno %d", errno);
    return map;
  }
  uintptr_t vaddr = ((uintptr_t) map) | (paddr & LIBTEA_PFN_MASK);
  return (void*) vaddr;

  #else
  NO_WINDOWS_SUPPORT;
  return NULL;
  #endif

}

int libtea_unmap_address_range(size_t vaddr, size_t length){

  #if LIBTEA_LINUX	
  void* unmap_addr = (void*)(((uintptr_t) vaddr) & ~LIBTEA_PFN_MASK);
  if(munmap(unmap_addr, length)){
    libtea_info("Munmap failed in libtea_unmap_address_range, errno is %d. Tried to unmap memory range of size %zu at %p", errno, length, unmap_addr);
    return LIBTEA_ERROR;
  }
  else {
    return LIBTEA_SUCCESS;
  }
  
  #else
  NO_WINDOWS_SUPPORT;
  return LIBTEA_ERROR;	  
  #endif
}


size_t libtea_get_paging_root(libtea_instance* instance, pid_t pid) {

  #if LIBTEA_LINUX
  libtea_paging_root cr3;
  cr3.pid = (size_t)pid;
  cr3.root = 0;
  ioctl(instance->module_fd, LIBTEA_IOCTL_GET_ROOT, (size_t)&cr3);
  return cr3.root;

  #else
  size_t cr3 = 0;
  DWORD returnLength;
  if(!pid) pid = GetCurrentProcessId();
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_GET_CR3, (LPVOID)&pid, sizeof(pid), (LPVOID)&cr3, sizeof(cr3), &returnLength, 0);
  return (cr3 & ~0xfff);
  #endif

}


void libtea_set_paging_root(libtea_instance* instance, pid_t pid, size_t root) {
  libtea_paging_root cr3;
  cr3.pid = (size_t)pid;
  cr3.root = root;

  #if LIBTEA_LINUX
  ioctl(instance->module_fd, LIBTEA_IOCTL_SET_ROOT, (size_t)&cr3);

  #else
  DWORD returnLength;
  if (!pid) pid = GetCurrentProcessId();
  size_t info[2];
  info[0] = pid;
  info[1] = root;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_SET_CR3, (LPVOID)info, sizeof(info), (LPVOID)info, sizeof(info), &returnLength, 0);
  #endif
}


void libtea_flush_tlb(libtea_instance* instance, void* address) {

  #if LIBTEA_LINUX
  ioctl(instance->module_fd, LIBTEA_IOCTL_FLUSH_TLB, (size_t)address);

  #else
  size_t vaddr = (size_t)address;
  DWORD returnLength;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_FLUSH_TLB, (LPVOID)&vaddr, sizeof(vaddr), (LPVOID)&vaddr, sizeof(vaddr), &returnLength, 0);
  #endif

}


void libtea_paging_barrier(libtea_instance* instance) {
  libtea__arch_speculation_barrier();
  libtea_set_paging_root(instance, 0, libtea_get_paging_root(instance, 0));
  libtea__arch_speculation_barrier();
}


int libtea_switch_flush_tlb_implementation(libtea_instance* instance, int implementation) {
  #ifdef LIBTEA_LINUX
  if(ioctl(instance->module_fd, LIBTEA_IOCTL_SWITCH_FLUSH_TLB_IMPLEMENTATION, (size_t) implementation) != 0) {
    return LIBTEA_SUCCESS;
  }
  else{
    return LIBTEA_ERROR;
  }
  #else
  NO_WINDOWS_SUPPORT;
  return LIBTEA_ERROR;
  #endif
}


size_t libtea_get_memory_types(libtea_instance* instance) {
  size_t mt = 0;

  #if LIBTEA_LINUX
  ioctl(instance->module_fd, LIBTEA_IOCTL_GET_PAT, (size_t)&mt);

  #else
  DWORD returnLength;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_GET_PAT, (LPVOID)&mt, sizeof(mt), (LPVOID)&mt, sizeof(mt), &returnLength, 0);
  #endif

  return mt;
}


void libtea_set_memory_types(libtea_instance* instance, size_t mts) {
  #if LIBTEA_LINUX
  ioctl(instance->module_fd, LIBTEA_IOCTL_SET_PAT, mts);

  #else
  DWORD returnLength;
  DeviceIoControl(instance->module_fd, LIBTEA_IOCTL_GET_PAT, (LPVOID)&mts, sizeof(mts), (LPVOID)&mts, sizeof(mts), &returnLength, 0);
  #endif

}


char libtea_get_memory_type(libtea_instance* instance, unsigned char mt) {
  size_t mts = libtea_get_memory_types(instance);
  return libtea__arch_get_mt(mts, mt);
}


void libtea_set_memory_type(libtea_instance* instance, unsigned char mt, unsigned char value) {
  size_t mts = libtea_get_memory_types(instance);
  mts &= libtea__arch_set_mt(mt);
  mts |= ((size_t)value << (mt * 8));
  libtea_set_memory_types(instance, mts);
}


unsigned char libtea_find_memory_type(libtea_instance* instance, unsigned char type) {
  size_t mts = libtea_get_memory_types(instance);
  return libtea__arch_find_mt(mts, type);
}


int libtea_find_first_memory_type(libtea_instance* instance, unsigned char type) {

  #if LIBTEA_LINUX
  return __builtin_ffs(libtea_find_memory_type(instance, type)) - 1;

  #else
  DWORD index = 0;
  if (BitScanForward64(&index, libtea_find_memory_type(instance, type))) {
    return index;
  }
  else {
    return -1;
  }
  #endif

}


size_t libtea_apply_memory_type(size_t entry, unsigned char mt) {
  return libtea__arch_apply_mt(entry, mt);
}


int libtea_set_page_cacheability(libtea_instance* instance, void* page, unsigned char type) {
  libtea_page_entry entry = libtea_resolve_addr(instance, page, 0);
  int available_mt = libtea_find_first_memory_type(instance, type);
  if (available_mt == -1) {
    return LIBTEA_ERROR;
  }
  entry.pte = libtea_apply_memory_type(entry.pte, available_mt);
  entry.valid = LIBTEA_VALID_MASK_PTE;
  libtea_update_addr(instance, page, 0, &entry);
  return LIBTEA_SUCCESS;
}


unsigned char libtea_extract_memory_type(size_t entry) {
  return libtea__arch_extract_mt(entry);
}


const char* libtea_memory_type_to_string(unsigned char mt) {
  return libtea__arch_mt_to_string(mt);
}


void libtea_print_libtea_page_entry(libtea_page_entry entry) {
  if (entry.valid & LIBTEA_VALID_MASK_PGD) {
    printf("PGD of address\n");
    libtea_print_page_entry(entry.pgd);
  }
  if (entry.valid & LIBTEA_VALID_MASK_P4D) {
    printf("P4D of address\n");
    libtea_print_page_entry(entry.p4d);
  }
  if (entry.valid & LIBTEA_VALID_MASK_PUD) {
    printf("PUD of address\n");
    libtea_print_page_entry(entry.pud);
  }
  if (entry.valid & LIBTEA_VALID_MASK_PMD) {
    printf("PMD of address\n");
    libtea_print_page_entry(entry.pmd);
  }
  if (entry.valid & LIBTEA_VALID_MASK_PTE) {
    printf("PTE of address\n");
    libtea_print_page_entry(entry.pte);
  }
}


#define libtea_paging_print_bit(fmt, bit)                                            \
  printf((fmt), (bit));                                                                \
  printf("|");


void libtea_print_page_entry(size_t entry) {
  for (int i = 0; i < 4; i++) {
    libtea_print_page_entry_line(entry, i);
  }
}


void* libtea_remap_address(libtea_instance* instance, size_t vaddr, libtea_page_level level, size_t length, int prot, bool use_dev_mem){

  #if LIBTEA_LINUX
  size_t paddr = libtea_get_physical_address_at_level(instance, vaddr, level);
  void* new_mapping = libtea_map_physical_address_range(instance, paddr, length, prot, use_dev_mem);
  return new_mapping;

  #else
  NO_WINDOWS_SUPPORT;
  return NULL;
  #endif
}


uint64_t libtea_get_physical_address_width(){

  #if LIBTEA_INLINEASM && LIBTEA_X86
	uint32_t eax, ebx, ecx, edx;
	static uint64_t width = 0;
	
	//Cache the result to avoid VM exits from CPUID
	if(width == 0){
		eax = 0x80000008;
		ebx = 0;
		ecx = 0;
		edx = 0;
	  asm volatile ("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (eax), "b" (ebx), "c" (ecx), "d" (edx));
		width = (eax & 0xff);
	}
	return width;
  
  #else
  //TODO. is this also Intel only? AMD cpuid parsing is often different
  libtea_info("Error: libtea_get_physical_address_width is only supported on x86 and requires compiler support for inline assembly.");
  return 0;
  #endif

}


size_t libtea_get_physical_address_at_level(libtea_instance* instance, size_t vaddr, libtea_page_level level){

  #if LIBTEA_LINUX
  libtea_page_entry entry = libtea_resolve_addr(instance, (void*)vaddr, 0);
  uint64_t base = libtea__get_physical_base_address(entry, level);
  uint64_t index = libtea__get_virtual_address_index(entry, level);
  if(level == LIBTEA_PAGE){
    return base + index;
  }
  else {
    return base + index * 8;
  }

  #else
  NO_WINDOWS_SUPPORT;
  return LIBTEA_ERROR;
  #endif
}


//Code adapted from the WindowsInternals demos at https://github.com/zodiacon/WindowsInternals/blob/master/MemCombine/MemCombine.cpp
//Note: in order to compile this with MinGW GCC, you need to manually link in NTDLL with -lntdll flag
#if LIBTEA_WINDOWS
#pragma comment(lib, "ntdll")
#include <Winternl.h>

#ifdef __cplusplus
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled);
extern "C" NTSTATUS NTAPI NtSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength);
#else
extern NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled);
extern NTSTATUS NTAPI NtSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength);
#endif

typedef struct {
	HANDLE Handle;
	ULONG_PTR PagesCombined;
	ULONG Flags;
} libtea_memory_combine_information_ex;
#endif


#if LIBTEA_ENABLE_WINDOWS_MEMORY_DEDUPLICATION
long long libtea_force_memory_deduplication(){

  #if LIBTEA_WINDOWS
  BOOLEAN enabled;
  /* Request SE_PROF_SINGLE_PROCESS_PRIVILEGE == 13L */
  int status = RtlAdjustPrivilege(13L, true, false, &enabled);
  if(status != 0) {
    libtea_info("Could not obtain SE_PROF_SINGLE_PROCESS_PRIVILEGE in libtea_force_memory_deduplication: status %d.\n", status);
  }
  libtea_memory_combine_information_ex info = {0};
  /* Currently don't offer option to just combine "common pages" (pages which are all 0s or all 1s), but can implement this by setting info.Flags to 4 instead */
	status = NtSetSystemInformation((SYSTEM_INFORMATION_CLASS)130, &info, sizeof(info));
	if (status != 0) {
		libtea_info("Error calling NtSetSystemInformation in libtea_force_memory_deduplication: status %d\n", status);
		return status;
	}
	return (long long)info.PagesCombined;

  #else
  libtea_info("libtea_force_memory_deduplication is only supported on Windows.");
  return 0;
  #endif

}
#endif
