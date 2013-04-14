/*
   The dynamic array.
   The array will grow or shrink according to the current size.
   The add and remove operation is of amotized cost of O(1).
 */

#include <stdlib.h>
#include "darr.h"

darr_t *new_darr()
{
    darr_t *p;
    uint32_t *arr;
    p = malloc(sizeof(darr_t));
    if(!p)
        return NULL;
    
    arr = malloc(sizeof(uint32_t) * DARR_INIT_ELEM_NUM);
    if(!arr)
    {
        free(p);
        return NULL;
    }
    p->max_elem = DARR_INIT_ELEM_NUM;
    p->curr_elem = 0;
    p->arr = arr;

    return p;
}

/*
    Double the size of the array.
 */
static int extend_darr(darr_t *darr)
{
    uint32_t *new_arr;
    size_t new_max = darr->max_elem * 2;

    new_arr = realloc(darr->arr, new_max);
    if(new_arr == NULL)
       return -1;
    
    darr->max_elem = new_max;
    darr->arr = new_arr;
    return 0;
}

/*
    Reduce the array size by half  
 */
static void shrink_darr(darr_t *darr)
{
    uint32_t *new_arr;
    size_t new_max = darr->max_elem / 2;
    
    new_arr = realloc(darr->arr, new_max);
    if(!new_arr)
        return ;

    darr->max_elem = new_max;
    darr->arr = new_arr;

    return ;
}

/* get the index of an element. If exist repeated elements,
   the index of the first appears one will be returned.
   (size_t)-1 will be returned is the element is not found.
 */
size_t get_elem_idx(darr_t *darr, uint32_t elem)
{
    size_t i;
    for(i = 0; i < darr->curr_elem; i++)
    {
        if(darr->arr[i] == elem)
            return i;
    }

    return (size_t)-1;
}

/*
    add element to the end of the arry.
    The array size may be doubled, if the current array is full
 */
int add_elem(darr_t *darr, uint32_t elem)
{
    if(darr->curr_elem == darr->max_elem)
    {
        if(-1 == extend_darr(darr))
            return -1;
    }

    darr->arr[darr->curr_elem] = elem;
    (darr->curr_elem)++;
    return 0;
}

/* 
   merge two array
 */
void merge_darr(darr_t *dest, darr_t *src)
{
    if(!dest || !src)
        return ;

    size_t i;
    for(i = 0; i < src->curr_elem; ++i)
    {
        add_elem(dest, src->arr[i]);
    }
}

/*
   Remove an element by index. The index of elements after
   one element remove may be different from the index before the
   remove. The caller should reget the index of an element after
   remove.
 */
int rm_elem_by_idx(darr_t *darr, size_t elem_idx)
{
    if(elem_idx >= darr->curr_elem)
        return -1;
    
    // use last one to replace the current one;
    darr->arr[elem_idx] = darr->arr[darr->curr_elem - 1];
    (darr->curr_elem)--;

    // reduce the size of the array if needed
    if(darr->curr_elem < darr->max_elem / 4)
        shrink_darr(darr);

    return 0;
}


void destroy_darr(darr_t *darr)
{
    free(darr->arr);
    free(darr);
}
