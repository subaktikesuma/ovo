//
// Created by fuqiuluo on 25-1-22.
//

#ifndef OVO_MMUHACK_H
#define OVO_MMUHACK_H

#include <asm/pgtable.h>

pte_t *page_from_virt(unsigned long addr);

int protect_rodata_memory(unsigned nr);

int unprotect_rodata_memory(unsigned nr);

#endif //OVO_MMUHACK_H
