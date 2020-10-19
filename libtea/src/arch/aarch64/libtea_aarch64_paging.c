
/* See LICENSE file for license and copyright information */

/* Start libtea_aarch64_paging.c */
//---------------------------------------------------------------------------

#if LIBTEA_AARCH64

#include "libtea_arch_paging.h"
#include "libtea_aarch64_paging.h"


libtea_inline void libtea__arch_print_page_entry_line(size_t entry, int line){
  if (line == 0 || line == 3) {
    printf("+--+--+--+---+-+--+------------------+--+-+-+-+--+---+-+\n");
  }
  if (line == 1) {
    printf("| ?| ?|XN|PXN|C| ?|        PFN       |NG|A|S|P|NS|MAI|T|\n");
  }
  if (line == 2) {
    printf("|");
    libtea_paging_print_bit("%2d", (LIBTEA_B(entry, 63) << 4) | (LIBTEA_B(entry, 62) << 3) | (LIBTEA_B(entry, 61) << 2) | (LIBTEA_B(entry, 60) << 1) | LIBTEA_B(entry, 59));
    libtea_paging_print_bit("%2d", (LIBTEA_B(entry, 58) << 3) | (LIBTEA_B(entry, 57) << 2) | (LIBTEA_B(entry, 56) << 1) | LIBTEA_B(entry, 55));
    libtea_paging_print_bit(" %d", LIBTEA_B(entry, 54));
    libtea_paging_print_bit(" %d ", LIBTEA_B(entry, 53));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, 52));
    libtea_paging_print_bit("%2d", (LIBTEA_B(entry, 51) << 3) | (LIBTEA_B(entry, 50) << 2) | (LIBTEA_B(entry, 49) << 1) | LIBTEA_B(entry, 48));
    printf(" %16p |", (void*)((entry >> 12) & ((1ull << 36) - 1)));
    libtea_paging_print_bit(" %d", LIBTEA_B(entry, 11));
    libtea_paging_print_bit("%d", LIBTEA_B(entry, 10));
    libtea_paging_print_bit("%d", (LIBTEA_B(entry, 9) << 1) | LIBTEA_B(entry, 8));
    libtea_paging_print_bit("%d", (LIBTEA_B(entry, 7) << 1) | LIBTEA_B(entry, 6));
    libtea_paging_print_bit(" %d", LIBTEA_B(entry, 5));
    libtea_paging_print_bit(" %d ", (LIBTEA_B(entry, 4) << 2) | (LIBTEA_B(entry, 3) << 1) | LIBTEA_B(entry, 2));
    libtea_paging_print_bit("%d", (LIBTEA_B(entry, 1) << 1) | LIBTEA_B(entry, 0));
    printf("\n");
  }
}

libtea_inline void libtea__arch_get_paging_definitions(libtea_instance* instance){
  instance->paging_definition.has_pgd = 1;
  instance->paging_definition.has_p4d = 0;
  instance->paging_definition.has_pud = 0;
  instance->paging_definition.has_pmd = 1;
  instance->paging_definition.has_pt = 1;
  instance->paging_definition.pgd_entries = 9;
  instance->paging_definition.p4d_entries = 0;
  instance->paging_definition.pud_entries = 0;
  instance->paging_definition.pmd_entries = 9;
  instance->paging_definition.pt_entries = 9;
  instance->paging_definition.page_offset = 12;
}


libtea_inline size_t libtea__arch_set_pfn(){
  return ~(((1ull << 36) - 1) << 12);
}


libtea_inline size_t libtea__arch_get_pfn(size_t pte){
  return (pte & (((1ull << 36) - 1) << 12)) >> 12;
}


libtea_inline char libtea__arch_get_mt(size_t mts, unsigned char mt){
  return ((mts >> (mt * 8)) & 0xff);
}


libtea_inline const char* libtea__arch_mt_to_string(unsigned char mt) {
  static char mts[16];
  int i;
  mts[0] = 0;
  for (i = 0; i < 2; i++) {
    strcat(mts, i == 0 ? "I" : "O");
    if ((mt & 0xf) == ((mt >> 4) & 0xf)) strcpy(mts, "");
    switch ((mt >> (i * 4)) & 0xf) {
      case 0:
        strcat(mts, "DM");
        break;
      case 1: /* Fall through */
      case 2: /* Fall through */
      case 3:
        strcat(mts, "WT");
        break;
      case 4:
        strcat(mts, "UC");
        break;
      case 5: /* Fall through */
      case 6: /* Fall through */
      case 7:
        strcat(mts, "WB");
        break;
      case 8: /* Fall through */
      case 9: /* Fall through */
      case 10: /* Fall through */
      case 11:
        strcat(mts, "WT");
        break;
      case 12: /* Fall through */
      case 13: /* Fall through */
      case 14: /* Fall through */
      case 15:
        strcat(mts, "WB");
    }
  }
  return mts;
}


libtea_inline size_t libtea__arch_set_mt(unsigned char mt){
  return  ~(0xff << (mt * 8));
}


libtea_inline unsigned char libtea__arch_find_mt(size_t mts, unsigned char type){
  unsigned char found = 0;
  int i;
  for (i = 0; i < 8; i++) {
    if (((mts >> (i * 8)) & 0xff) == type) {
      found |= (1 << i);
    }
    else {
      unsigned char plow, phigh;
      plow = (mts >> (i * 8)) & 0xf;
      phigh = ((mts >> (i * 8)) >> 4) & 0xf;
      if ((plow == phigh) && (plow == type)) {
        found |= (1 << i);
      }
    }
  }
  return found;
}


libtea_inline size_t libtea__arch_apply_mt(size_t entry, unsigned char mt) {
  entry &= ~0x1c;
  entry |= (mt & 7) << 2;
  return entry;
}


libtea_inline unsigned char libtea__arch_extract_mt(size_t entry){
  return (entry >> 2) & 7;
}


libtea_inline uint64_t libtea__arch_get_physical_base_address(libtea_page_entry entry, libtea_page_level level){
  libtea_info("libtea_get_physical_base_address is unsupported on AArch64.");
  return 0;
}


libtea_inline uint64_t libtea__arch_get_virtual_address_index(libtea_page_entry entry, libtea_page_level level){
  libtea_info("libtea_get_virtual_address_index is unsupported on AArch64");
  return 0;
}


#endif //LIBTEA_AARCH64


/* End libtea_aarch64_paging.c */
//---------------------------------------------------------------------------