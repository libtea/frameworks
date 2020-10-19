
/* See LICENSE file for license and copyright information */

/* Start libtea_ppc64_paging.c */
//---------------------------------------------------------------------------

#if LIBTEA_PPC

#include "libtea_arch_paging.h"
#include "libtea_ppc64_paging.h"
#include <sys/platform/ppc.h>


#define LIBTEA_PPC_UNSUPPORTED() libtea_info("Paging is not yet supported on PPC64.")


libtea_inline void libtea__arch_print_page_entry_line(size_t entry, int line){
  LIBTEA_PPC_UNSUPPORTED();
}

libtea_inline void libtea__arch_get_paging_definitions(libtea_instance* instance){
  LIBTEA_PPC_UNSUPPORTED();
}


libtea_inline size_t libtea__arch_set_pfn(){
  LIBTEA_PPC_UNSUPPORTED();
  return 0;
}


libtea_inline size_t libtea__arch_get_pfn(size_t pte){
  LIBTEA_PPC_UNSUPPORTED();
  return 0;
}


libtea_inline char libtea__arch_get_mt(size_t mts, unsigned char mt){
  LIBTEA_PPC_UNSUPPORTED();
  return 'A';
}


libtea_inline const char* libtea__arch_mt_to_string(unsigned char mt) {
  LIBTEA_PPC_UNSUPPORTED();
  return NULL;
}


libtea_inline size_t libtea__arch_set_mt(unsigned char mt){
  LIBTEA_PPC_UNSUPPORTED();
  return 0;
}


libtea_inline unsigned char libtea__arch_find_mt(size_t mts, unsigned char type){
  LIBTEA_PPC_UNSUPPORTED();
  return 'A';
}


libtea_inline size_t libtea__arch_apply_mt(size_t entry, unsigned char mt) {
  LIBTEA_PPC_UNSUPPORTED();
  return 0;
}


libtea_inline unsigned char libtea__arch_extract_mt(size_t entry) {
  LIBTEA_PPC_UNSUPPORTED();
  return 'A';
}


libtea_inline uint64_t libtea__arch_get_physical_base_address(libtea_page_entry entry, libtea_page_level level){
  LIBTEA_PPC_UNSUPPORTED();
  return 0;
}


libtea_inline uint64_t libtea__arch_get_virtual_address_index(libtea_page_entry entry, libtea_page_level level){
  LIBTEA_PPC_UNSUPPORTED();
  return 0;
}


#endif //LIBTEA_PPC


/* End libtea_ppc64_paging.c */
//---------------------------------------------------------------------------