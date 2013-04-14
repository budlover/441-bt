#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "ht.h"


/* 
   convert the num to the bucket index
 */
size_t uint_to_idx(void *key, size_t key_len, size_t bucket_size)
{
    return (size_t)key % bucket_size;
}

int cmp_int(const void *int1, size_t key_len, const void *int2)
{
    if((long)int1 == (long)int2)
        return 0;

    return -1;
}

/* 
   convert the sting to the bucket index
 */
size_t str_to_idx(void *key, size_t key_len, size_t bucket_size)
{
    size_t sum = 0;
    char *c = key;
    while(*c)
    {
        sum += *c;
        c++;
    }
    sum = sum % bucket_size;

    return sum;
}

int cmpstr(const void *str1, size_t key_len, const void *str2)
{
    return strcmp(str1, str2);
}

size_t mem_to_idx(void *key, size_t key_len, size_t bucket_size)
{
    size_t sum = 0;
    uint8_t *c = key;
    size_t n;
    for(n = 0; n < key_len; ++n)
    {
        sum += c[n];
    }

    sum = sum % bucket_size;

    return sum;
}

int cmpmem(const void *mem1, size_t key_len, const void *mem2)
{
    return memcmp(mem1, mem2, key_len);
}

void init_ht(hash_info_t *ht, void **bucket_base, size_t bucket_sz, size_t key_len,
             HT_KEY_TYPE k_type)
{
    assert(ht);
    ht->table_base = bucket_base;
    ht->bucket_size = bucket_sz;
    ht->entr_cnt = 0;
    ht->key_len = key_len;

    switch(k_type)
    {
    case HT_KEY_TYPE_STR:
        ht->key_to_idx = str_to_idx;
        ht->cmp_key = cmpstr;
        break;

    case HT_KEY_TYPE_NUM:
        ht->key_to_idx = uint_to_idx;
        ht->cmp_key = cmp_int;
        break;

    case HT_KEY_TYPE_MEM:
        ht->key_to_idx = mem_to_idx;
        ht->cmp_key = cmpmem;
        break;

    default:
        assert(0);
    }
}
