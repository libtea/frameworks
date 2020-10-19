#include "../../libtea.h"
#include "utest.h"
#include <time.h>

UTEST_STATE();

#if LIBTEA_LINUX
#define PAGE_ALIGN_CHAR char __attribute__((aligned(4096)))
#else
#define PAGE_ALIGN_CHAR __declspec(align(4096)) char
#endif

libtea_instance* instance;

PAGE_ALIGN_CHAR page1[4096];
PAGE_ALIGN_CHAR page2[4096];
PAGE_ALIGN_CHAR scratch[4096];
PAGE_ALIGN_CHAR accessor[4096];

// =========================================================================
//                             Helper functions
// =========================================================================

#if LIBTEA_LINUX
size_t hrtime() {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return t1.tv_sec * 1000 * 1000 * 1000ULL + t1.tv_nsec;
}
#else
size_t hrtime() {
    __int64 wintime; 
    GetSystemTimePreciseAsFileTime((FILETIME*)&wintime);
    return wintime;
}
#endif

typedef void (*access_time_callback_t)(libtea_instance*, void*);

int access_time_ext(void *ptr, size_t MEASUREMENTS, access_time_callback_t cb) {
  size_t start = 0, end = 0, sum = 0;

  for (int i = 0; i < MEASUREMENTS; i++) {
    start = hrtime();
    *((volatile size_t*)ptr);
    end = hrtime();
    sum += end - start;
    if(cb) cb(instance, ptr);
  }

  return (int)(10 * sum / MEASUREMENTS);
}

int access_time(void *ptr) {
  return access_time_ext(ptr, 1000000, NULL);
}

int entry_equal(libtea_page_entry* e1, libtea_page_entry* e2) {
    int diff = 0;
    if((e1->valid & LIBTEA_VALID_MASK_PGD) && (e2->valid & LIBTEA_VALID_MASK_PGD)) {
        diff |= e1->pgd ^ e2->pgd;
    }
    if((e1->valid & LIBTEA_VALID_MASK_P4D) && (e2->valid & LIBTEA_VALID_MASK_P4D)) {
        diff |= e1->p4d ^ e2->p4d;
    }    
    if((e1->valid & LIBTEA_VALID_MASK_PUD) && (e2->valid & LIBTEA_VALID_MASK_PUD)) {
        diff |= e1->pud ^ e2->pud;
    }
    if((e1->valid & LIBTEA_VALID_MASK_PMD) && (e2->valid & LIBTEA_VALID_MASK_PMD)) {
        diff |= e1->pmd ^ e2->pmd;
    }
    if((e1->valid & LIBTEA_VALID_MASK_PTE) && (e2->valid & LIBTEA_VALID_MASK_PTE)) {
        diff |= e1->pte ^ e2->pte;
    }
    return !diff;
}

// =========================================================================
//                             Resolving addresses
// =========================================================================


UTEST(resolve, resolve_basic) {
    libtea_page_entry vm = libtea_resolve_addr(instance, page1, 0);
    ASSERT_TRUE(vm.pgd);
    ASSERT_TRUE(vm.pte);
    ASSERT_TRUE(vm.valid & LIBTEA_VALID_MASK_PTE);
    ASSERT_TRUE(vm.valid & LIBTEA_VALID_MASK_PGD);    
}

UTEST(resolve, resolve_valid_mask) {
    libtea_page_entry vm = libtea_resolve_addr(instance, page1, 0);
    if(vm.valid & LIBTEA_VALID_MASK_PGD) ASSERT_TRUE(vm.pgd);
    if(vm.valid & LIBTEA_VALID_MASK_P4D) ASSERT_TRUE(vm.p4d);
    if(vm.valid & LIBTEA_VALID_MASK_PMD) ASSERT_TRUE(vm.pmd);
    if(vm.valid & LIBTEA_VALID_MASK_PUD) ASSERT_TRUE(vm.pud);
    if(vm.valid & LIBTEA_VALID_MASK_PTE) ASSERT_TRUE(vm.pte);
}

UTEST(resolve, resolve_deterministic) {
    libtea_page_entry vm1 = libtea_resolve_addr(instance, page1, 0);
    libtea_page_entry vm2 = libtea_resolve_addr(instance, page1, 0);
    ASSERT_TRUE(entry_equal(&vm1, &vm2));
}

UTEST(resolve, resolve_different) {
    libtea_page_entry vm1 = libtea_resolve_addr(instance, page1, 0);
    libtea_page_entry vm2 = libtea_resolve_addr(instance, page2, 0);
    ASSERT_FALSE(entry_equal(&vm1, &vm2));
}

UTEST(resolve, resolve_invalid) {
    libtea_page_entry vm1 = libtea_resolve_addr(instance, 0, 0);
    ASSERT_FALSE(vm1.valid & LIBTEA_VALID_MASK_PTE);
}

UTEST(resolve, resolve_invalid_pid) {
    libtea_page_entry vm1 = libtea_resolve_addr(instance, page1, -1);
    ASSERT_FALSE(vm1.valid);
}

UTEST(resolve, resolve_page_offset) {
    libtea_page_entry vm1 = libtea_resolve_addr(instance, page1, 0);
    libtea_page_entry vm2 = libtea_resolve_addr(instance, page1 + 1, 0);
    vm1.vaddr = vm2.vaddr = 0;
    ASSERT_TRUE(entry_equal(&vm1, &vm2));
    libtea_page_entry vm3 = libtea_resolve_addr(instance, page1 + 1024, 0);
    vm1.vaddr = vm3.vaddr = 0;
    ASSERT_TRUE(entry_equal(&vm1, &vm3));
    libtea_page_entry vm4 = libtea_resolve_addr(instance, page1 + 4095, 0);
    vm1.vaddr = vm4.vaddr = 0;
    ASSERT_TRUE(entry_equal(&vm1, &vm4));
}


// =========================================================================
//                             Updating addresses
// =========================================================================

UTEST(update, nop) {
    libtea_page_entry vm1 = libtea_resolve_addr(instance, scratch, 0);
    ASSERT_TRUE(vm1.valid);
    size_t valid = vm1.valid;
    vm1.valid = 0;
    libtea_update_addr(instance, scratch, 0, &vm1);
    vm1.valid = valid;
    libtea_page_entry vm2 = libtea_resolve_addr(instance, scratch, 0);
    ASSERT_TRUE(entry_equal(&vm1, &vm2));
}

UTEST(update, pte_nop) {
    libtea_page_entry vm1 = libtea_resolve_addr(instance, scratch, 0);
    ASSERT_TRUE(vm1.valid);
    size_t valid = vm1.valid;
    vm1.valid = LIBTEA_VALID_MASK_PTE;
    libtea_update_addr(instance, scratch, 0, &vm1);
    vm1.valid = valid;
    libtea_page_entry vm2 = libtea_resolve_addr(instance, scratch, 0);
    ASSERT_TRUE(entry_equal(&vm1, &vm2));
}

UTEST(update, new_pte) {
    libtea_page_entry vm = libtea_resolve_addr(instance, scratch, 0);
    libtea_page_entry vm1 = libtea_resolve_addr(instance, scratch, 0);
    ASSERT_TRUE(vm1.valid);
    size_t pte = vm1.pte;
    vm1.pte = libtea_set_pfn(vm1.pte, 0x1234);
    vm1.valid = LIBTEA_VALID_MASK_PTE;
    libtea_update_addr(instance, scratch, 0, &vm1);
    
    libtea_page_entry check = libtea_resolve_addr(instance, scratch, 0);
    ASSERT_NE((size_t)libtea_cast(check.pte, libtea_pte).pfn, libtea_get_pfn(pte));
    ASSERT_EQ((size_t)libtea_cast(check.pte, libtea_pte).pfn, 0x1234);
    
    vm1.valid = LIBTEA_VALID_MASK_PTE;
    vm1.pte = pte;
    libtea_update_addr(instance, scratch, 0, &vm1);
    
    libtea_page_entry vm2 = libtea_resolve_addr(instance, scratch, 0);
    ASSERT_TRUE(entry_equal(&vm, &vm2));
}

// =========================================================================
//                                  PTEs
// =========================================================================

UTEST(pte, get_pfn) {
    libtea_page_entry vm = libtea_resolve_addr(instance, page1, 0);
    ASSERT_EQ(libtea_get_pfn(vm.pte), (size_t)libtea_cast(vm.pte, libtea_pte).pfn);
}

UTEST(pte, get_pte_pfn) {
    libtea_page_entry vm = libtea_resolve_addr(instance, page1, 0);
    ASSERT_EQ(libtea_get_addr_pfn(instance, page1, 0), (size_t)libtea_cast(vm.pte, libtea_pte).pfn);
}

UTEST(pte, get_pte_pfn_invalid) {
    ASSERT_FALSE(libtea_get_addr_pfn(instance, 0, 0));
}

UTEST(pte, pte_present) {
    libtea_page_entry vm = libtea_resolve_addr(instance, page1, 0);
    ASSERT_EQ((size_t)libtea_cast(vm.pte, libtea_pte).present, LIBTEA_PAGE_PRESENT);
}

UTEST(pte, pte_set_pfn_basic) {
    size_t entry = 0;
    ASSERT_EQ(entry, libtea_set_pfn(entry, 0));
    ASSERT_NE(entry, libtea_set_pfn(entry, 1));
    ASSERT_EQ(entry, libtea_set_pfn(libtea_set_pfn(entry, 1234), 0));
    ASSERT_GT(libtea_set_pfn(entry, 2), libtea_set_pfn(entry, 1));
    entry = (size_t)-1;
    ASSERT_NE(0, libtea_set_pfn(entry, 0));
}

UTEST(pte, pte_set_pfn) {
    ASSERT_TRUE(accessor[0] == 2);
    size_t accessor_pfn = libtea_get_addr_pfn(instance, accessor, 0);
    ASSERT_TRUE(accessor_pfn);
    size_t page1_pfn = libtea_get_addr_pfn(instance, page1, 0);
    ASSERT_TRUE(page1_pfn);
    size_t page2_pfn = libtea_get_addr_pfn(instance, page2, 0);
    ASSERT_TRUE(page2_pfn);
    libtea_set_addr_pfn(instance, accessor, 0, page1_pfn);
    ASSERT_TRUE(accessor[0] == 0);
    libtea_set_addr_pfn(instance, accessor, 0, page2_pfn);
    ASSERT_TRUE(accessor[0] == 1);
    libtea_set_addr_pfn(instance, accessor, 0, accessor_pfn);
    ASSERT_TRUE(accessor[0] == 2);
}


// =========================================================================
//                             Physical Pages
// =========================================================================

UTEST(page, read) {
    char buffer[4096];
    size_t pfn = libtea_get_addr_pfn(instance, page1, 0);
    ASSERT_TRUE(pfn);
    libtea_read_physical_page(instance, pfn, buffer);
    ASSERT_TRUE(!memcmp(buffer, page1, sizeof(buffer)));
    pfn = libtea_get_addr_pfn(instance, page2, 0);
    ASSERT_TRUE(pfn);
    libtea_read_physical_page(instance, pfn, buffer);
    ASSERT_TRUE(!memcmp(buffer, page2, sizeof(buffer)));
}

UTEST(page, write) {
    char buffer[4096];
    size_t pfn = libtea_get_addr_pfn(instance, scratch, 0);
    ASSERT_TRUE(pfn);
    libtea_write_physical_page(instance, pfn, page1);
    libtea_read_physical_page(instance, pfn, buffer);
    ASSERT_TRUE(!memcmp(page1, buffer, sizeof(buffer)));
    libtea_write_physical_page(instance, pfn, page2);
    libtea_read_physical_page(instance, pfn, buffer);
    ASSERT_TRUE(!memcmp(page2, buffer, sizeof(buffer)));
}

// =========================================================================
//                                Paging
// =========================================================================

UTEST(paging, get_root) {
    size_t root = libtea_get_paging_root(instance, 0);
    ASSERT_TRUE(root);
}

UTEST(paging, get_root_deterministic) {
    size_t root = libtea_get_paging_root(instance, 0);
    ASSERT_TRUE(root);
    size_t root_check = libtea_get_paging_root(instance, 0);
    ASSERT_EQ(root, root_check);   
}

UTEST(paging, get_root_invalid_pid) {
    size_t root = libtea_get_paging_root(instance, -1);
    ASSERT_FALSE(root);
}

UTEST(paging, root_page_aligned) {
    size_t root = libtea_get_paging_root(instance, 0);
    ASSERT_TRUE(root);
    ASSERT_FALSE(root % libtea_get_pagesize(instance));
}

UTEST(paging, correct_root) {
    size_t buffer[4096 / sizeof(size_t)];
    size_t root = libtea_get_paging_root(instance, 0);
    libtea_read_physical_page(instance, root / libtea_get_pagesize(instance), (char*)buffer);
    libtea_page_entry vm = libtea_resolve_addr(instance, 0, 0);
    ASSERT_EQ(vm.pgd, buffer[0]);
}

// =========================================================================
//                               Memory Types
// =========================================================================

UTEST(memtype, get) {
    ASSERT_TRUE(libtea_get_memory_types(instance));
}

UTEST(memtype, get_deterministic) {
    ASSERT_EQ(libtea_get_memory_types(instance), libtea_get_memory_types(instance));
}

UTEST(memtype, uncachable) {
    ASSERT_NE(libtea_find_first_memory_type(instance, LIBTEA_UNCACHEABLE), -1);
}

UTEST(memtype, writeback) {
    ASSERT_NE(libtea_find_first_memory_type(instance, LIBTEA_WRITE_BACK), -1);
}

UTEST(memtype, find_first) {
    ASSERT_TRUE(libtea_get_memory_type(instance, libtea_find_first_memory_type(instance, LIBTEA_UNCACHEABLE)) == LIBTEA_UNCACHEABLE);
    ASSERT_TRUE(libtea_get_memory_type(instance, libtea_find_first_memory_type(instance, LIBTEA_WRITE_BACK)) == LIBTEA_WRITE_BACK);
}

UTEST(memtype, apply) {
    size_t entry = 0;
    ASSERT_NE(libtea_apply_memory_type(entry, 1), entry);
    ASSERT_EQ(libtea_apply_memory_type(entry, 0), entry);
}

UTEST(memtype, extract) {
    ASSERT_TRUE(libtea_extract_memory_type(libtea_apply_memory_type(0, 5)) == 5);
    ASSERT_TRUE(libtea_extract_memory_type(libtea_apply_memory_type((size_t)-1, 2)) == 2);
}

UTEST(memtype, uncachable_access_time) {
    int uc_mt = libtea_find_first_memory_type(instance, LIBTEA_UNCACHEABLE);
    ASSERT_NE(uc_mt, -1);
    int wb_mt = libtea_find_first_memory_type(instance, LIBTEA_WRITE_BACK);
    ASSERT_NE(wb_mt, -1);
    
    int before = access_time(scratch);
    
    libtea_page_entry entry = libtea_resolve_addr(instance, scratch, 0);
    size_t pte = entry.pte;
    ASSERT_TRUE(entry.valid);
    ASSERT_TRUE(entry.pte);
    entry.pte = libtea_apply_memory_type(entry.pte, uc_mt);
    entry.valid = LIBTEA_VALID_MASK_PTE;
    libtea_update_addr(instance, scratch, 0, &entry);   
    
    int uc = access_time(scratch);
    
    entry.pte = pte;
    entry.valid = LIBTEA_VALID_MASK_PTE;
    libtea_update_addr(instance, scratch, 0, &entry);   
    
    int after = access_time(scratch);

    ASSERT_LT(after + 5, uc);
    ASSERT_LT(before + 5, uc);
}

// =========================================================================
//                               TLB
// =========================================================================


UTEST(tlb, access_time) {
    int flushed = access_time_ext(scratch, 100, libtea_flush_tlb);
    int normal = access_time_ext(scratch, 100, NULL);
    ASSERT_GT(flushed, normal);
}

#if LIBTEA_LINUX
UTEST(tlb, invalid_flush_tlb_implementation) {
    int ret = libtea_switch_flush_tlb_implementation(instance, 3);
    ASSERT_TRUE(ret);
}

UTEST(tlb, valid_flush_tlb_implementation) {
    int ret = libtea_switch_flush_tlb_implementation(instance, LIBTEA_FLUSH_TLB_KERNEL);
    ASSERT_FALSE(ret);
}

UTEST(tlb, access_time_kernel_flush_tlb) {
    libtea_switch_flush_tlb_implementation(instance, LIBTEA_FLUSH_TLB_KERNEL);
    int flushed = access_time_ext(scratch, 100, libtea_flush_tlb);
    int normal = access_time_ext(scratch, 100, NULL);
    ASSERT_GT(flushed, normal);
}

UTEST(tlb, access_time_custom_flush_tlb) {
    libtea_switch_flush_tlb_implementation(instance, LIBTEA_FLUSH_TLB_CUSTOM);
    int flushed = access_time_ext(scratch, 100, libtea_flush_tlb);
    int normal = access_time_ext(scratch, 100, NULL);
    ASSERT_GT(flushed, normal);
}
#endif

int main(int argc, const char *const argv[]) {
    instance = libtea_init();
    if(instance == NULL) {
        printf("Could not initialize Libtea, did you load the kernel module?\n");
        return 1;
    }
    memset(scratch, 0, sizeof(scratch));
    memset(page1, 0, sizeof(page1));
    memset(page2, 1, sizeof(page2));
    memset(accessor, 2, sizeof(accessor));

    int result = utest_main(argc, argv);
 
    libtea_cleanup(instance);
    return result;
}
