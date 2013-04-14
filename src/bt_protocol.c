#include <arpa/inet.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>

#include "bt_protocol.h"
#include "sha.h"

#define MAGIC 15441
#define VERSION 1

#define MAX_HEAD_LEN sizeof(bt_header_t)
#define MAX_PAYLOAD_LEN 1400


int is_valid_pkt_head(bt_header_t *head)
{
    if(head->h_len > MAX_HEAD_LEN)
    {
        return 0;
    }

    if(head->pkt_len - head->h_len > MAX_PAYLOAD_LEN)
    {
        return 0;
    }

    return 1;
}


size_t calc_whohas_size(size_t entr_cnt)
{
    return sizeof(bt_header_t) + sizeof(uint32_t) + SHA1_HASH_SIZE * entr_cnt;
}

size_t calc_ihave_size(size_t entr_cnt)
{
    return sizeof(bt_header_t) + sizeof(uint32_t) + SHA1_HASH_SIZE * entr_cnt;
}


void fill_whohas(char *buffer, hash_set_t *reqset)
{
    bt_header_t *h = (bt_header_t *)buffer;
    uint32_t *cnt = (uint32_t *)(buffer + sizeof(bt_header_t));
    hash_v_t *hash = (hash_v_t *)(cnt + 1);

    h->magic = MAGIC;
    h->version = VERSION;
    h->type = PRO_TYPE_WHOHAS;
    h->h_len = sizeof(bt_header_t);
    h->pkt_len = sizeof(bt_header_t) + sizeof(uint32_t) 
                 + SHA1_HASH_SIZE * reqset->cnt;

    assert(reqset->cnt > 0); 
    *cnt = (uint32_t)reqset->cnt;
    memcpy(hash, reqset->hash, reqset->cnt * sizeof(hash_v_t));
}

void fill_ihave(char *buffer, hash_set_t *haveset)
{
    bt_header_t *h = (bt_header_t *)buffer;
    uint32_t *cnt = (uint32_t *)(buffer + sizeof(bt_header_t));
    hash_v_t *hash = (hash_v_t *)(cnt + 1);

    h->magic = MAGIC;
    h->version = VERSION;
    h->type = PRO_TYPE_IHAVE;
    h->h_len = sizeof(bt_header_t);
    h->pkt_len = sizeof(bt_header_t) + sizeof(uint32_t) 
                 + SHA1_HASH_SIZE * haveset->cnt;
 
    assert(haveset->cnt > 0); 
    *cnt = (uint32_t)haveset->cnt;
    memcpy(hash, haveset->hash, haveset->cnt * sizeof(hash_v_t));

}

size_t calc_get_size()
{
    return sizeof(bt_header_t) + SHA1_HASH_SIZE;
}

void fill_get(char *buffer, uint8_t *hash)
{
    bt_header_t *h = (bt_header_t *)buffer;
    uint8_t *payload = (uint8_t *)(buffer + sizeof(bt_header_t));

    h->magic = MAGIC;
    h->version = VERSION;
    h->type = PRO_TYPE_GET;
    h->h_len = sizeof(bt_header_t);
    h->pkt_len = sizeof(bt_header_t) + SHA1_HASH_SIZE;
    
    memcpy(payload, hash, SHA1_HASH_SIZE);
}

size_t calc_data_size(size_t data_sz)
{
    return sizeof(bt_header_t) + data_sz;
}

void fill_data(char *buffer, char *src, size_t src_sz, uint32_t seq_num)
{
    bt_header_t *h = (bt_header_t *)buffer;
    uint8_t *payload = (uint8_t *)(buffer + sizeof(bt_header_t));

    h->magic = MAGIC;
    h->version = VERSION;
    h->type = PRO_TYPE_DATA;
    h->h_len = sizeof(bt_header_t);
    h->pkt_len = sizeof(bt_header_t) + src_sz;
    h->seq_num = seq_num;
    
    memcpy(payload, src, src_sz);
}

char *get_data_payload(char *pkt, size_t *pl_sz)
{
    assert(pkt);
    bt_header_t *h = (bt_header_t *)pkt;
    char *payload = pkt + sizeof(bt_header_t);

    assert(h->type == PRO_TYPE_DATA);
    *pl_sz = h->pkt_len - h->h_len;
    return payload;
}

size_t calc_ack_size()
{
    return sizeof(bt_header_t);
}

void fill_ack(char *buffer, uint32_t ack_num)
{
    bt_header_t *h = (bt_header_t *)buffer;

    h->magic = MAGIC;
    h->version = VERSION;
    h->type = PRO_TYPE_ACK;
    h->h_len = sizeof(bt_header_t);
    h->pkt_len = sizeof(bt_header_t);
    h->ack_num = ack_num;
}

size_t calc_denied_size()
{
    return sizeof(bt_header_t);
}

void fill_denied(char *buffer)
{
    bt_header_t *h = (bt_header_t *)buffer;

    h->magic = MAGIC;
    h->version = VERSION;
    h->type = PRO_TYPE_DENIED;
    h->h_len = sizeof(bt_header_t);
    h->pkt_len = sizeof(bt_header_t);
}


void dbg_print_pkt(char *pkt)
{
    bt_header_t *h = (bt_header_t *)pkt;

    fprintf(stderr, "************************************************\n");
    fprintf(stderr, "magic num %hu\n", h->magic);
    fprintf(stderr, "ver %hhu\n", h->version);
    fprintf(stderr, "type %hhu\n", h->type);
    fprintf(stderr, "seq num %u\n", h->seq_num);
    fprintf(stderr, "ack num %u\n", h->ack_num);
    fprintf(stderr, "payload size %u\n", h->pkt_len - h->h_len);
    fprintf(stderr, "************************************************\n");

}
/*
int is_valid_pkt()
{
}
*/
