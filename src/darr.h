#ifndef _DARR_H_
#define _DARR_H_
#include <stdint.h>
#include <stdlib.h>

#define DARR_INIT_ELEM_NUM 4

typedef struct darr
{
    size_t max_elem;
    size_t curr_elem;
    uint32_t *arr;
} darr_t;


darr_t *new_darr();

size_t get_elem_idx(darr_t *darr, uint32_t elem);

void merge_darr(darr_t *dest, darr_t *src);

int add_elem(darr_t *darr, uint32_t elem);

int rm_elem_by_idx(darr_t *darr, size_t elem_idx);

void destroy_darr(darr_t *darr);

#endif
