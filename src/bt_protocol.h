#ifndef _BT_PROTOCOL_H_
#define _BT_PROTOCOL_H_
#include <stdint.h>

#include "req.h"

#include "pkts.h"

typedef struct bt_header
{
    uint16_t    magic;
    uint8_t     version;
    uint8_t     type;
    uint16_t    h_len;   // header len
    uint16_t    pkt_len; // packet len, including the header len
    uint32_t    seq_num;
    uint32_t    ack_num;
} bt_header_t;

int is_valid_pkt_head(bt_header_t *head);

size_t calc_whohas_size(size_t entr_cnt);
size_t calc_ihave_size(size_t entr_cnt);
size_t calc_get_size();
size_t calc_data_size(size_t data_sz);
size_t calc_ack_size();
size_t calc_denied_size();

void fill_whohas(char *buffer, hash_set_t *reqset);
void fill_ihave(char *buffer, hash_set_t *haveset);
void fill_get(char *buffer, uint8_t *hash);
void fill_data(char *buffer, char *src, size_t src_sz, uint32_t seq_num);
void fill_ack(char *buffer, uint32_t ack_num);
void fill_denied(char *buffer);

char *get_data_payload(char *pkt, size_t *pl_sz);

void dbg_print_pkt(char *pkt);

#endif
