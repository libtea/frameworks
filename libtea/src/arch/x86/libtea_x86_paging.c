
/* See LICENSE file for license and copyright information */

/* Start libtea_x86_paging.c */
//---------------------------------------------------------------------------

#if LIBTEA_X86

#include "libtea_arch_paging.h"
#include "libtea_x86_paging.h"


libtea_inline void libtea__arch_print_page_entry_line(size_t entry, int line){
  if (line == 0 || line == 3) printf("+--+------------------+-+-+-+-+-+-+-+-+--+--+-+-+-+\n");
  if (line == 1) printf("|NX|       PFN        |H|?|?|?|G|S|D|A|UC|WT|U|W|P|\n");
  if (line == 2) {
    printf("|");
    libtea_paging_print_bit(" %d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_NX));
    printf(" %16p |", (void*)((entry >> 12) & ((1ull << 40) - 1)));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_PAT_LARGE));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_SOFTW3));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_SOFTW2));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_SOFTW1));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_GLOBAL));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_PSE));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_DIRTY));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_ACCESSED));
    libtea_paging_print_bit(" %d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_PCD));
    libtea_paging_print_bit(" %d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_PWT));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_USER));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_RW));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, LIBTEA_PAGE_BIT_PRESENT));
    printf("\n");
  }
}


libtea_inline void libtea__arch_get_paging_definitions(libtea_instance* instance){
  instance->paging_definition.has_pgd = 1;
  instance->paging_definition.has_p4d = 0;
  instance->paging_definition.has_pud = 1;
  instance->paging_definition.has_pmd = 1;
  instance->paging_definition.has_pt = 1;
  instance->paging_definition.pgd_entries = 9;
  instance->paging_definition.p4d_entries = 0;
  instance->paging_definition.pud_entries = 9;
  instance->paging_definition.pmd_entries = 9;
  instance->paging_definition.pt_entries = 9;
  instance->paging_definition.page_offset = 12;
}


libtea_inline size_t libtea__arch_set_pfn(){
  return  ~(((1ull << 40) - 1) << 12);
}


libtea_inline size_t libtea__arch_get_pfn(size_t pte){
  return (pte & (((1ull << 40) - 1) << 12)) >> 12;
}


libtea_inline char libtea__arch_get_mt(size_t mts, unsigned char mt){
  return ((mts >> (mt * 8)) & 7);
}


libtea_inline const char* libtea__arch_mt_to_string(unsigned char mt) {
  const char* mts[] = { "UC", "WC", "Rsvd", "Rsvd", "WT", "WP", "WB", "UC-", "Rsvd" };
  if (mt <= 7) return mts[mt];
  return NULL;
}


libtea_inline size_t libtea__arch_set_mt(unsigned char mt){
  return ~(7 << (mt * 8));
}


libtea_inline unsigned char libtea__arch_find_mt(size_t mts, unsigned char type){
  unsigned char found = 0;
  int i;
  for (i = 0; i < 8; i++) {
    if (((mts >> (i * 8)) & 7) == type) found |= (1 << i);
  }
  return found;
}


libtea_inline size_t libtea__arch_apply_mt(size_t entry, unsigned char mt) {
  entry &= ~((1ull << LIBTEA_PAGE_BIT_PWT) | (1ull << LIBTEA_PAGE_BIT_PCD) | (1ull << LIBTEA_PAGE_BIT_PAT));
  if (mt & 1) entry |= (1ull << LIBTEA_PAGE_BIT_PWT);
  if (mt & 2) entry |= (1ull << LIBTEA_PAGE_BIT_PCD);
  if (mt & 4) entry |= (1ull << LIBTEA_PAGE_BIT_PAT);
  return entry;
}


libtea_inline unsigned char libtea__arch_extract_mt(size_t entry){
  return (!!(entry & (1ull << LIBTEA_PAGE_BIT_PWT))) | ((!!(entry & (1ull << LIBTEA_PAGE_BIT_PCD))) << 1) | ((!!(entry & (1ull << LIBTEA_PAGE_BIT_PAT))) << 2);
}


libtea_inline uint64_t libtea__arch_get_physical_base_address(libtea_page_entry entry, libtea_page_level level){
  switch(level){
    case LIBTEA_PGD:
      libtea_info("TODO not implemented yet, returning pgd here instead of pgd_phys_address");
      return entry.pgd;
    case LIBTEA_PUD:
      return LIBTEA_PGD_PHYS(entry.pgd);
    case LIBTEA_PMD:
      if(!LIBTEA_PUD_PS(entry.pud)){
        libtea_info("WARNING: PUD assertion failed in libtea_get_physical_base_address, PMD address returned will be wrong");
      }
      return LIBTEA_PUD_PS_0_PHYS(entry.pud);
    case LIBTEA_PTE:
      if(!LIBTEA_PUD_PS(entry.pud) && !LIBTEA_PMD_PS(entry.pmd)){
        libtea_info("WARNING: PUD or PMD assertion failed in libtea_get_physical_base_address, PTE address returned will be wrong");
      }
      return LIBTEA_PMD_PS_0_PHYS(entry.pmd);
    case LIBTEA_PAGE:
    //Intentional fall-through
    default:
      if(LIBTEA_PUD_PS(entry.pud)){
        return LIBTEA_PUD_PS_1_PHYS(entry.pud);
      }
      if(LIBTEA_PMD_PS(entry.pmd)){
        return LIBTEA_PMD_PS_1_PHYS(entry.pmd);
      }
      return LIBTEA_PT_PHYS(entry.pte);
  }
}


libtea_inline uint64_t libtea__arch_get_virtual_address_index(libtea_page_entry entry, libtea_page_level level){
  switch(level){
    case LIBTEA_PGD:
      return LIBTEA_PGD_INDEX(entry.vaddr);
    case LIBTEA_PUD:
      return LIBTEA_PUD_INDEX(entry.vaddr);
    case LIBTEA_PMD:
    {
      if(!LIBTEA_PUD_PS(entry.pud)){
        libtea_info("WARNING: PUD assertion failed in libtea_get_virtual_address_index, PMD address returned will be wrong");
      }
      return LIBTEA_PMD_INDEX(entry.vaddr);
    }
    case LIBTEA_PTE:
    {
      if(!LIBTEA_PUD_PS(entry.pud) && !LIBTEA_PMD_PS(entry.pmd)){
        libtea_info("WARNING: PUD or PMD assertion failed in libtea_get_virtual_address_index, PTE address returned will be wrong");
      }
      return LIBTEA_PTE_INDEX(entry.vaddr);
    }
    case LIBTEA_PAGE:
    //Intentional fall-through
    default:
    {
      if(LIBTEA_PUD_PS(entry.pud)){
        return LIBTEA_PAGE1GiB_INDEX(entry.vaddr);
      }
      else if(LIBTEA_PMD_PS(entry.pmd)){
        return LIBTEA_PAGE2MiB_INDEX(entry.vaddr);
      }
      else return LIBTEA_PAGE_INDEX(entry.vaddr);
    }
  }
}


#endif //LIBTEA_X86


/* End libtea_x86_paging.c */
//---------------------------------------------------------------------------