#ifndef _PKTS_H_
#define _PKTS_H_

#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>


#define DATA_TIMEOUT 15000000 // data time, 10 second
#define GET_TIMEOUT 3000000 // get time, 3 second

typedef enum _PRO_TYPE
{
    PRO_TYPE_WHOHAS = 0,
    PRO_TYPE_IHAVE, 
    PRO_TYPE_GET,
    PRO_TYPE_DATA,
    PRO_TYPE_ACK,
    PRO_TYPE_DENIED
} PRO_TYPE;

typedef struct pd_pkt
{
    struct pd_pkt *next;
    int type;         // one of pro_type
    uint32_t seq_num; // only used for data type
    long left_time;
    struct sockaddr_in addr;
    size_t pl_sz;    //payload size
    char payload[1];
}  __attribute__((packed)) pd_pkt_t;

pd_pkt_t *new_pd_pkt(size_t pl_sz, struct sockaddr_in addr, 
                            int pkt_type, uint32_t seq_num);


typedef struct recv_pkt
{
    struct recv_pkt *next;
    uint32_t seq_num;
    size_t pl_sz;    //payload size
    char payload[1];

}  __attribute__((packed)) recv_pkt_t;

recv_pkt_t *new_recv_pkt(uint32_t seq_num, size_t pl_sz, char *data);

void reset_left_time(pd_pkt_t *pkt);

#endif
