
/* See LICENSE file for license and copyright information */

#ifndef LIBTEA_ARCH_PAGING_H
#define LIBTEA_ARCH_PAGING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libtea_common.h"


typedef enum {LIBTEA_PGD, LIBTEA_PUD, LIBTEA_PMD, LIBTEA_PTE, LIBTEA_PAGE} libtea_page_level;


libtea_inline void libtea__arch_print_page_entry_line(size_t entry, int line);


libtea_inline void libtea__arch_get_paging_definitions(libtea_instance* instance);


libtea_inline size_t libtea__arch_set_pfn();


libtea_inline size_t libtea__arch_get_pfn(size_t pte);


libtea_inline char libtea__arch_get_mt(size_t mts, unsigned char mt);


libtea_inline const char* libtea__arch_mt_to_string(unsigned char mt);


libtea_inline size_t libtea__arch_set_mt(unsigned char mt);


libtea_inline unsigned char libtea__arch_find_mt(size_t mts, unsigned char type);


libtea_inline size_t libtea__arch_apply_mt(size_t entry, unsigned char mt);


libtea_inline unsigned char libtea__arch_extract_mt(size_t entry);


libtea_inline uint64_t libtea__arch_get_physical_base_address(libtea_page_entry entry, libtea_page_level level);


libtea_inline uint64_t libtea__arch_get_virtual_address_index(libtea_page_entry entry, libtea_page_level level);


#ifdef __cplusplus
}
#endif


#endif //LIBTEA_ARCH_PAGING_H