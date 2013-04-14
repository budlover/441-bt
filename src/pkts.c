#include <assert.h>

#include "pkts.h"
#include "memory.h"

pd_pkt_t *new_pd_pkt(size_t pl_sz, struct sockaddr_in addr, 
                            int pkt_type, uint32_t seq_num)
{
    pd_pkt_t *new_pkt;
    new_pkt = malloc(sizeof(pd_pkt_t) + pl_sz - 1);
        if(!new_pkt)
            return NULL;
    bzero(new_pkt, sizeof(pd_pkt_t) + pl_sz - 1);

    new_pkt->next = NULL;

    new_pkt->type = pkt_type;
    new_pkt->seq_num = seq_num;  // only meaningful for data type pkt

    new_pkt->addr = addr;
    new_pkt->pl_sz = pl_sz;
    return new_pkt;
}

recv_pkt_t *new_recv_pkt(uint32_t seq_num, size_t pl_sz, char *data)
{
    recv_pkt_t *new_pkt;
    new_pkt = malloc(sizeof(recv_pkt_t) + pl_sz - 1);
    if(!new_pkt)
       return NULL;
    new_pkt->next = NULL;
    
    new_pkt->seq_num = seq_num;
    new_pkt->pl_sz = pl_sz;
    memcpy(new_pkt->payload, data, pl_sz);
    return new_pkt;
}


void reset_left_time(pd_pkt_t *pkt)
{
    if(pkt->type == PRO_TYPE_GET)
    {
        pkt->left_time = GET_TIMEOUT;
    }
    else
    {
        pkt->left_time = DATA_TIMEOUT;
    }
}
