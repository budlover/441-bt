#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <stdint.h>

#include "sha.h"

typedef struct chunk_map
{
    uint32_t chk_id;
    uint8_t hash[SHA1_HASH_SIZE]; //original hash, not hash string
    int  is_local;   // does this peer have the file
    struct chunk_map *next;
} chunk_map_t;

int init_mst_chk_map(const char *mst_chunk_file, int *mstdata_fd);

// MUST be called after init_mst_chk_map
int init_has_chk_map(const char *has_chk_file);

int add_has_chunk(uint8_t *hash);
chunk_map_t *do_i_have_chunk(uint8_t *hash);

void dbg_print_conf();
#endif
