#ifndef _REQ_H_
#define _REQ_H_
#include "sha.h"
#include "chunk.h"
#include "config.h"
#include "darr.h"
#include "pkts.h"

#define INIT_CNGT_WIN_SZ 1
#define INIT_SSTHRESH    64
#define MIN_SSTHRESH 2

#define RECV_WIN_SZ 64

#define RCB_TIMEOUT 30000000 //chunk request timeout, 30 second
#define SCB_TIMEOUT 30000000 //receiver down, 30 seconds

#define PD_RCB_TIMEOUT 60000000 //pending request timeout, 60 second

#define AVOIDANCE_TIMEOUT 3000000 // timeer for congestion avoidance

#define ENLARGE_SLIDING_WIN 1
#define SHRINK_SLIDING_WIN 0

typedef enum _CNGST_STATE
{
    CNGST_STATE_SLOWSTART = 0, // slow start
    CNGST_STATE_AVOIDANCE // congestion avoidance
} CNGST_STATE;

typedef struct hash_v
{
    uint8_t hash[SHA1_HASH_SIZE];
} __attribute__((packed)) hash_v_t;

// request set, template for contruct whohas
typedef struct hash_set
{
    struct hash_set *next;
    int cnt;
    hash_v_t hash[1];
} __attribute__((packed)) hash_set_t;

hash_set_t *get_ihave_hash_set(hash_v_t hash[ ], int cnt);
void free_hash_sets(hash_set_t *head);

/********************************************************************/
// request control block, info about a to receive/receving chunk
typedef struct rcb
{ 
    uint32_t wr_chk_id;           // the chunk id to write the chunk to 
    chunk_map_t *chk_map;         // pointer to chunk-id mapping 

    long left_time;                // reserved now

    darr_t *have_peers;            // the peer that have the chunk

    size_t next_byte;         // next _byte to write
    char  *buffer;            // pointer to buffer of size  BT_CHUNK_SIZE
   
    uint32_t win_sz;              // windows size
    uint32_t last_pkt_read;
    uint32_t last_pkt_expt;
    uint32_t last_pkt_rcvd;
    
    recv_pkt_t *recv_head;

    pd_pkt_t *pd_get;
    
         
    struct rcb *next;
} rcb_t;

rcb_t *load_get_chunks(const char *get_chunk_file, int *cnt);

hash_set_t *get_req_hash_sets(rcb_t *head, int cnt);

void update_have_peer(rcb_t *head, hash_v_t hash[], int cnt, short id);
void destroy_single_rcb(rcb_t *rcb);
void free_rcbs(rcb_t *head);
void reset_rcb(rcb_t *rcb);
void update_last_pkt_expt(rcb_t *rcb);

int is_valid_seq_num(rcb_t *rcb, uint32_t seq_num);
int insert_recv_pkt(rcb_t *rcb, recv_pkt_t *pkt);
// return 1 if get full block
int read_buf_data(rcb_t *rcb);
int write_chunk_to_file(rcb_t *rcb);

int is_consistent_chunk(rcb_t *rcb);

void add_unresp_get(rcb_t *rcb, pd_pkt_t *pkt);
void remove_rspd_get(rcb_t *rcb);
int is_pd_req_timeout(rcb_t *rcb, long elapsed);
pd_pkt_t *is_get_timeout(rcb_t *rcb, long time_elapsed);
int is_rcb_timeout(rcb_t *rcb, long elapsed);
void reset_rcb_timeout(rcb_t *rcb);


/*******************************************************************/

// sender control block, info about a sending chunk
typedef struct scb
{
    uint32_t scb_id;
    uint32_t seq_num;       // the next seq_num to use
    uint32_t start_byte;
    uint32_t next_byte;
    uint32_t end_delim;     // one past last byte to send

    long left_time;                // reserved now

    uint32_t last_ack_recv;       // last reviced ack 
    uint32_t in_row_ack_cnt;      // continuous ack count, for dup ack

    CNGST_STATE state; 
    long avoid_time;

    uint32_t ssthresh;
    uint32_t win_sz;              // windows size
    uint32_t last_pkt_acked;
    uint32_t last_pkt_sent;
    uint32_t max_pkt_sent;

    pd_pkt_t *pd_pkt_head;

} scb_t;

void update_sliding_win_timer(scb_t *scb, long time_elapsed);


scb_t *create_scb(uint32_t chk_id);
void destroy_scb(scb_t *scb);

int is_valid_ack_num(scb_t *scb, uint32_t ack_num);
int is_dup_acks(scb_t *scb);
void update_last_ack_recv(scb_t *scb, uint32_t ack_num);
void update_sliding_win(scb_t *scb, int is_increase, uint32_t ack_num,
                        int is_fast_retran);
size_t get_next_pkt_data(char *buff, size_t buf_sz, scb_t *scb);
void rollback_last_pkt_send(scb_t *scb, size_t sd_sz);
pd_pkt_t *detach_next_unresp_pkt(scb_t *scb);
pd_pkt_t *detach_unresp_pkt_by_seqnum(scb_t *scb, uint32_t seq_num);

void add_unresp_pkt(scb_t *scb, pd_pkt_t *pkt);
void remove_respd_pkt(scb_t *scb, int pkt_type, uint32_t ack_num);
//pd_pkt_t *get_timeout_pkt(scb_t *scb, long *time_elapsed);
pd_pkt_t *get_timeout_pkts(scb_t *scb, long time_elapsed);
pd_pkt_t *get_timeout_pkt(scb_t *scb, long time_elapsed);

void reset_scb_timeout(scb_t *scb);
int is_sending_finish(scb_t *scb);

int is_scb_timeout(scb_t *scb, long elapsed);
#endif
