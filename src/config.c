#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "config.h"
#include "str_helper.h"
#include "ht.h"
#include "chunk.h"

#define CHKM_BUCKET_LEN 200
#define CONF_LINE_LEN 255

#define MAX_FPATH_LEN 255
// chunk id mapping hash table
hash_info_t g_chunkmap_ht;
static chunk_map_t *chkm_bucket[CHKM_BUCKET_LEN];

static char has_chunk_file[MAX_FPATH_LEN + 1];

// load the master chunk file mapping
int init_mst_chk_map(const char *mst_chunk_file, int *mstdata_fd)
{
    FILE *fp = NULL;
    char buff[CONF_LINE_LEN + 1];
    chunk_map_t *p = NULL;
    uint32_t chk_id;
    int mst_data_fd = -1;
    
    init_ht(&g_chunkmap_ht, (void **)chkm_bucket, CHKM_BUCKET_LEN,
            SHA1_HASH_SIZE, HT_KEY_TYPE_MEM);

    fp = fopen(mst_chunk_file, "r");
    if(!fp)
    {
        goto err;
    }

    // get the master data file path
    if(!fgets(buff, CONF_LINE_LEN + 1, fp))
    {
        goto err;
    }

    if(strncmp(buff, "File: ", strlen("File: ")))
    {
        goto err;
    }
    else  // open the master data file
    {
        buff[strlen(buff) - 1] = '\0'; // set the '\n' to '\0'
        if(-1 == (mst_data_fd = open(buff + strlen("File: "), O_RDONLY)))
        {
            fprintf(stderr, "Can't open master data file\n");
            goto err;
        }
        *mstdata_fd = mst_data_fd;
    }
/************************************************************************/
    // skip the "Chunks:"
    if(!fgets(buff, CONF_LINE_LEN + 1, fp))
    {
        goto err;
    }
    if(strncmp(buff, "Chunks:", strlen("Chunks:")))
    {
        goto err;
    }
/************************************************************************/

    // load the chunks
    while(NULL != fgets(buff, CONF_LINE_LEN + 1, fp))
    {
        char *str;
        p = (chunk_map_t *)malloc(sizeof(chunk_map_t));
        if(NULL == p)
            goto err;
        p->is_local = 0;

        str = strtok(buff, " \n");
        if(NULL == str)
           goto err;
        if(0 != str_to_uint32(buff, &chk_id))
           goto err; 
        p->chk_id = chk_id;

        str = strtok(NULL, " \n");
        if(NULL == str)
           goto err;
        if(strlen(str) != SHA1_HASH_SIZE * 2)
            goto err; 
        hex2binary(str, SHA1_HASH_SIZE * 2, p->hash);
        
        HT_INSERT(&g_chunkmap_ht, chunk_map_t, p->hash, p);
    }
    fclose(fp);

    return 0;

err:
    if(p)
        free(p); 
    if(fp)
        fclose(fp);
    if(-1 != mst_data_fd)
        close(mst_data_fd);

    return -1;
}

// load the has chunk mapping for host node
// MUST be called after init_mst_chk_map
int init_has_chk_map(const char *has_chk_file)
{

    assert(g_chunkmap_ht.table_base != NULL);

    FILE *fp = NULL;
    char buff[CONF_LINE_LEN + 1];
    uint8_t hash[SHA1_HASH_SIZE];
    chunk_map_t *p = NULL;
    uint32_t chk_id;

    if(strlen(has_chk_file) > MAX_FPATH_LEN)
        goto err;
    strcpy(has_chunk_file, has_chk_file);

    fp = fopen(has_chunk_file, "r");
    if(!fp)
    {
        goto err;
    }
 
    // load the chunks
    while(NULL != fgets(buff, CONF_LINE_LEN + 1, fp))
    {
        char *str;

        // skip chunk id
        str = strtok(buff, " \n");
        if(NULL == str)
           goto err;
        if(0 != str_to_uint32(buff, &chk_id))
           goto err; 
        
        str = strtok(NULL, " \n");
        if(NULL == str)
           goto err;
        if(strlen(str) != SHA1_HASH_SIZE * 2)
            goto err; 
        
        hex2binary(str, SHA1_HASH_SIZE * 2, hash);

        // find and set is local
        HT_FIND(&g_chunkmap_ht, chunk_map_t, hash, hash, p);
        if(!p) // no such chunk
        {
            fprintf(stderr, "Invalid hash_chunk_file entry\n");
            goto err;
        }
        p->is_local = 1;        
    }   
    
    fclose(fp);
    dbg_print_conf();
    return 0;
 
err:
    if(fp)
        fclose(fp);
    return -1;
}


// add a has chunks for the host node, the has file will also be modified
int add_has_chunk(uint8_t *hash)
{
    chunk_map_t *p = NULL;
    FILE *fp;
    char hash_str[SHA1_HASH_SIZE * 2 + 1];
    char id[15];

    HT_FIND(&g_chunkmap_ht, chunk_map_t, hash, hash, p);
    if(!p)
        return -1;
    if(p->is_local)
        return -1;

    p->is_local = 1;

    fp = fopen(has_chunk_file, "a");
    if(!fp)
        return -1;
   
    sprintf(id, "%u ", p->chk_id);  // id and a ' ' (space)
    binary2hex(hash, SHA1_HASH_SIZE, hash_str);

    fwrite(id, 1, strlen(id), fp);
    fwrite(hash_str, 1, strlen(hash_str), fp);
    fwrite("\n", 1, 1, fp);
    fclose(fp);

    return 0;
}

void dbg_print_conf()
{
    chunk_map_t *p;
    size_t n;
    char buff[SHA1_HASH_SIZE * 2 + 1];

    for(n = 0; n < g_chunkmap_ht.bucket_size; ++n)
    {
        p = (chunk_map_t *)g_chunkmap_ht.table_base[n];
        while(p)
        {
            binary2hex(p->hash, SHA1_HASH_SIZE, buff);
            printf("chunk id: %u, hash: %s, is local?: %d\n", p->chk_id, 
                    buff, p->is_local);
            p = p->next;
        }
    }
}

chunk_map_t *do_i_have_chunk(uint8_t *hash)
{
    chunk_map_t *p;
    HT_FIND(&g_chunkmap_ht, chunk_map_t, hash, hash, p);
    if(!p)
        return NULL;
    if(p->is_local)
    {
        return p;
    }
    else
    {
        return NULL;
    }
}
