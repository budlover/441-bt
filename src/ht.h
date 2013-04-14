#ifndef _HT_H_
#define _HT_H_
#include <assert.h>
#include <stdio.h>

typedef enum
{
    HT_KEY_TYPE_STR = 0,
    HT_KEY_TYPE_NUM,
    HT_KEY_TYPE_MEM
} HT_KEY_TYPE;

typedef struct hash_inf
{
    void **table_base; 
    size_t bucket_size;
    size_t entr_cnt;
    size_t key_len; // lenghth of the key, not size of key
    size_t (*key_to_idx)(void *key, size_t key_len, size_t bucket_size);
    int (*cmp_key)(const void *key_i, size_t key_len, const void *key);
} hash_info_t;

#define HT_INSERT(HASH_INFO, STRUCT_TYPE, INSERT_KEY, NODE)   \
do{\
    STRUCT_TYPE **table = (STRUCT_TYPE **)(HASH_INFO)->table_base;\
    size_t idx = (HASH_INFO)->key_to_idx((void *)(long)INSERT_KEY, (HASH_INFO)->key_len, (HASH_INFO)->bucket_size); \
    STRUCT_TYPE *node = table[idx]; \
    table[idx] = NODE;\
    (NODE)->next = node;\
    (HASH_INFO)->entr_cnt = (HASH_INFO)->entr_cnt + 1;\
}while(0)

#define HT_FIND(HASH_INFO, STRUCT_TYPE, KEY_NAME, TARGET_KEY, P) \
do{\
    STRUCT_TYPE **table = (STRUCT_TYPE **)(HASH_INFO)->table_base;\
    size_t idx = (HASH_INFO)->key_to_idx((void *)(long)TARGET_KEY, (HASH_INFO)->key_len, (HASH_INFO)->bucket_size); \
    STRUCT_TYPE *node = table[idx]; \
    while(node)\
    {\
        if(!(HASH_INFO)->cmp_key((void *)(long)node->KEY_NAME, (HASH_INFO)->key_len, (void *)(long)TARGET_KEY))\
            break;\
        else\
            node = node->next;\
    }\
    P = node;\
}while(0)


/*
    User should make sure the node is inside the hash table by looking up
    it through HT_FIND first.
    User is reponsible for freeing the node!!!
*/
#define HT_REMOVE(HASH_INFO, STRUCT_TYPE, KEY_NAME, TARGET_KEY)\
do{\
    STRUCT_TYPE **table = (STRUCT_TYPE **)(HASH_INFO)->table_base;\
    size_t idx = (HASH_INFO)->key_to_idx((void *)(long)TARGET_KEY, (HASH_INFO)->key_len, (HASH_INFO)->bucket_size); \
    STRUCT_TYPE *curr = table[idx]; \
    STRUCT_TYPE **pre_next = table + idx; \
    while(curr)\
    {\
        if(!(HASH_INFO)->cmp_key((void *)(long)curr->KEY_NAME, ((HASH_INFO)->key_len, void *)(long)TARGET_KEY))\
            break;\
        else\
        {\
            pre_next = &curr->next;\
            curr = curr->next;\
        }\
    }\
    assert(curr);\
    *pre_next = curr->next;\
    (HASH_INFO)->entr_cnt = (HASH_INFO)->entr_cnt - 1;\
}while(0)


/*
    shallow remove.
    User should make sure that the node in the hash table do NOT
    contain further dynamically allocated memory.
*/
#define HT_REMOVE_ALL(HASH_INFO, STRUCT_TYPE)\
do{\
    STRUCT_TYPE **table = (STRUCT_TYPE **)(HASH_INFO)->table_base;\
    STRUCT_TYPE *tmp;\
    STRUCT_TYPE *to_free;\
    size_t i;\
    for(i = 0; i < (HASH_INFO)->bucket_size; ++i)\
    {\
        tmp = table[i]; \
        while(tmp)\
        {\
           to_free = tmp;\
           tmp = tmp->next;\
           free(to_free);\
           (HASH_INFO)->entr_cnt = (HASH_INFO)->entr_cnt - 1;\
        }\
    }\
}while(0)

void init_ht(hash_info_t *ht, void **bucket_base, size_t bucket_sz, size_t key_len,
             HT_KEY_TYPE k_type);

#endif
