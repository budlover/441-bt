#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <memory.h>

#include "req.h"
#include "str_helper.h"
#include "ht.h"
#include "sha.h"
#include "bt_parse.h"
#include "bt_info.h"
#include "chunk.h"
#include "dbg_helper.h"
#include "helper.h"
#include "winsz_logger.h"

#define DUP_ACK_THRESH 3
#define GET_LINE_LEN 255
#define MAX_REQ_ENTR 70

extern hash_info_t g_chunkmap_ht;
extern bt_info_t g_bt_inf;

static uint32_t scb_id = 0;

/*********************** hash_v_t ****************************/
hash_set_t *get_ihave_hash_set(hash_v_t hash[ ], int cnt)
{
    int n;
    hash_set_t *p = NULL;
    p = malloc(sizeof(hash_set_t) + (cnt - 1) * sizeof(hash_v_t));
    if(!p)
        return NULL;
    p->cnt = 0;
    p->next = NULL;

    for(n = 0; n < cnt; ++n)
    {
        if(do_i_have_chunk(hash[n].hash))
        {
            memcpy(&p->hash[p->cnt], &hash[n], sizeof(hash_v_t));
            (p->cnt)++;
        }
    }

    if(p->cnt == 0)
    {
        free(p);
        p = NULL;
    }

    return p;
}

void free_hash_sets(hash_set_t *head)
{
    hash_set_t *to_free;
    hash_set_t *p;

    to_free = head;
    while(to_free)
    {
        p = to_free;
        to_free = to_free->next;
        free(p);
    }
}

/********************** rcb **********************************/

int is_pd_req_timeout(rcb_t *rcb, long elapsed)
{
    if(rcb->left_time > elapsed)
    {
        rcb->left_time -= elapsed;
    }
    else
    {
        // reset time out
        dbg_print(2, "pd req timeout\n");
        rcb->left_time = PD_RCB_TIMEOUT;
        if(rcb->have_peers)
        {
            destroy_darr(rcb->have_peers);
            rcb->have_peers = NULL;
        }
        return 1;
    }
    
    return 0;
}

int is_valid_seq_num(rcb_t *rcb, uint32_t seq_num)
{
    if(rcb->last_pkt_read < seq_num && 
       seq_num <= rcb->last_pkt_read + rcb->win_sz)
    {
        return 1;
    } 
    else
    {
        return 0;
    }
}

static rcb_t *create_rcb()
{
    rcb_t *p = NULL;
    p = (rcb_t *)malloc(sizeof(rcb_t));
    if(!p)
        return NULL;
    bzero(p, sizeof(rcb_t));

    p->wr_chk_id = (uint32_t)-1;

    p->chk_map = NULL;

    p->left_time = PD_RCB_TIMEOUT;    
    p->have_peers = NULL; 
    
    p->next_byte = 0;
    p->buffer = NULL;
 
    p->win_sz = RECV_WIN_SZ;              // windows size
    p->last_pkt_read = 0;
    p->last_pkt_expt = 1;
    p->last_pkt_rcvd = 0;
 
    p->recv_head = NULL;              // datat buffer list

    p->pd_get = NULL;

    p->next = NULL;

    return p;
}

void free_rcbs(rcb_t *head)
{
    rcb_t *to_free = head;
    rcb_t *p;
    while(to_free)
    {
        p = to_free;
        to_free = to_free->next;
        if(p->buffer)
        {
            free(p->buffer);
        }
        
        if(p->have_peers)
        {
            free(p->have_peers);
        }

        free(p);
    }
}

rcb_t *load_get_chunks(const char *get_chunk_file, int *cnt)
{
    FILE *fp = NULL;
    char buff[GET_LINE_LEN + 1];
    uint8_t hash[SHA1_HASH_SIZE]; //original hash, not hash string
    uint32_t wr_chk_id;
    chunk_map_t *map;
    int req_cnt = 0;
    
    rcb_t *head = NULL;
    rcb_t *p = NULL;

    fp = fopen(get_chunk_file, "r");
    if(!fp)
    {
        return NULL;
    }

    // load the chunks
    while(NULL != fgets(buff, GET_LINE_LEN + 1, fp))
    {
        char *str;

        p = create_rcb();
        if(NULL == p)
            goto err;

        str = strtok(buff, " \n");
        if(NULL == str)
           goto err;
        if(0 != str_to_uint32(buff, &wr_chk_id))
           goto err; 
        p->wr_chk_id = wr_chk_id;

        str = strtok(NULL, " \n");
        if(NULL == str)
           goto err;
        if(strlen(str) != SHA1_HASH_SIZE * 2)
            goto err; 
        hex2binary(str, SHA1_HASH_SIZE * 2, hash);

        HT_FIND(&g_chunkmap_ht, chunk_map_t, hash, hash, map);
        if(!map)
        {
            free(p);
        }
        else
        {
            p->chk_map = map;
            p->next = head;
            head = p;
            req_cnt++;
        }
    }
    fclose(fp);
    *cnt = req_cnt;
    return head;
    
err:
    if(fp)
        fclose(fp);

    if(p)
        free(p);
    
    *cnt = req_cnt;

    return head;
}


// caller is responsible to free it after use
hash_set_t *get_req_hash_sets(rcb_t *head, int cnt)
{
    int set_cnt = 0;
    int n, m;
    hash_set_t *set_head = NULL;
    hash_set_t *p = NULL;
    set_cnt = (cnt + MAX_REQ_ENTR - 1) / MAX_REQ_ENTR; // round up
    int curr_cnt = 0;   // count for current set

    for(m = 0; m < set_cnt; m++)
    {
        curr_cnt = cnt > MAX_REQ_ENTR ? MAX_REQ_ENTR : cnt;
        cnt -= curr_cnt;

        p = malloc(sizeof(hash_set_t) + (curr_cnt - 1) * sizeof(hash_v_t));
        if(!p)
            return set_head;

        p->cnt = curr_cnt;
        for(n = 0; n < curr_cnt; ++n)
        {
            memcpy(p->hash[n].hash, head->chk_map->hash, SHA1_HASH_SIZE);
            head = head->next;
        }

        p->next = set_head;
        set_head = p;
    }

    assert(cnt == 0);
    return p;
}

void update_have_peer(rcb_t *head, hash_v_t hash[], int cnt, short id)
{
    rcb_t *p;
    chunk_map_t *chk_map;
    int n;

    for(n = 0; n < cnt; n++)
    {
        p = head;
        while(p)
        {
            chk_map = p->chk_map;
            assert(chk_map);
            if(!memcmp(chk_map->hash, hash[n].hash, SHA1_HASH_SIZE))
            {
                if(!p->have_peers)
                {
                    p->have_peers = new_darr();
                    if(!p->have_peers)
                        return ;
                }

                add_elem(p->have_peers, (uint32_t)id);
            }

            p = p->next;
        }
    }
}

int write_chunk_to_file(rcb_t *rcb)
{
    pwrite(g_bt_inf.wrfile_fd, rcb->buffer, BT_CHUNK_SIZE, 
           rcb->wr_chk_id * BT_CHUNK_SIZE);
    return 0;
}

void destroy_single_rcb(rcb_t *rcb)
{
    assert(rcb);
    if(rcb->buffer)
    {
        free(rcb->buffer);
    }

    if(rcb->have_peers)
    {
        destroy_darr(rcb->have_peers);
    }

    if(rcb->pd_get)
        free(rcb->pd_get);

    free(rcb);
}

int is_consistent_chunk(rcb_t *rcb)
{
    uint8_t hash[SHA1_HASH_SIZE];
    shahash((uint8_t *)rcb->buffer, BT_CHUNK_SIZE, hash);     
    if(!memcmp(hash, rcb->chk_map->hash, SHA1_HASH_SIZE))
    {
        return 1;
    }
    else
    {
        fprintf(stderr, "invalid chunk\n");
        return 0;
    }
}

void reset_rcb(rcb_t *rcb)
{
    recv_pkt_t *pkt = NULL;

    rcb->next_byte = 0;
    if(rcb->buffer)
    {
        free(rcb->buffer);
        rcb->buffer = NULL;
    }

    rcb->left_time = PD_RCB_TIMEOUT / 2;

    rcb->win_sz = RECV_WIN_SZ;              // windows size
    rcb->last_pkt_read = 0;
    rcb->last_pkt_expt = 1;
    rcb->last_pkt_rcvd = 0;
 
    pkt = rcb->recv_head;
    while(pkt)
    {
        rcb->recv_head = pkt->next;
        free(pkt);
        pkt = rcb->recv_head;
    }

    if(rcb->pd_get)
    {
        free(rcb->pd_get);
        rcb->pd_get = NULL;
    }

    rcb->next = NULL;
}

void update_last_pkt_expt(rcb_t *rcb)
{
    uint32_t seq = rcb->last_pkt_read + 1;
    recv_pkt_t *p = rcb->recv_head;
   
    while(p)
    {
        if(p->seq_num == seq)
        {
            seq++;
            rcb->last_pkt_expt = seq;
            p = p->next;
        }
        else
        {
            break;
        }
    }
    dbg_print(0, "expt pkt num is %u\n", rcb->last_pkt_expt);
}

int read_buf_data(rcb_t *rcb)
{
    uint32_t expt_seq = rcb->last_pkt_expt;
    recv_pkt_t *p = rcb->recv_head;

    while(p && p->seq_num <= expt_seq)
    {
        assert(p->seq_num != expt_seq);

        rcb->last_pkt_read++;

        memcpy(rcb->buffer + rcb->next_byte, 
               p->payload, p->pl_sz);
        rcb->next_byte += p->pl_sz;
        
        rcb->recv_head = p->next;
        free(p);
        p = rcb->recv_head;
    }
   
    if(rcb->next_byte == BT_CHUNK_SIZE) //get full block
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

// insert the received pkt to list in order of seq num
int insert_recv_pkt(rcb_t *rcb, recv_pkt_t *pkt)
{
    assert(pkt->next == NULL);
    recv_pkt_t *pre = NULL;
    recv_pkt_t *p = rcb->recv_head;

    while(p)
    {
        // pkt already buffered
        if(p->seq_num == pkt->seq_num)
        {
            return -1;
        }
        else if(p->seq_num < pkt->seq_num)
        {
            pre = p;
            p = p->next;
        }
        else  // insert before p
        {
            pkt->next = p;
            if(pre)
            {
                pre->next = pkt;
            }
            else // p is the first one
            {
                rcb->recv_head = pkt;
            }
            return 0;
        }
    }
    
    // insert at the end
    if(NULL == pre)  // empty list
    {
        rcb->recv_head = pkt;
    }
    else
    {
        pre->next = pkt;
    }
    return 0;
}

void add_unresp_get(rcb_t *rcb, pd_pkt_t *pkt)
{
    assert(pkt->next == NULL);
    assert(rcb->pd_get == NULL);
    rcb->pd_get = pkt;
} 

pd_pkt_t *is_get_timeout(rcb_t *rcb, long time_elapsed)
{
    pd_pkt_t *pd_get = NULL;
    
    pd_get = rcb->pd_get;

    if(pd_get)
    {
        if(time_elapsed < pd_get->left_time)
        {
            pd_get->left_time -= time_elapsed;
            return NULL;
        }
        else
        {
            rcb->pd_get = NULL;
            assert(pd_get->next == NULL);
            return pd_get;
        }
    }

    return pd_get;
}

void reset_rcb_timeout(rcb_t *rcb)
{
    assert(rcb);
    rcb->left_time = RCB_TIMEOUT;
}

int is_rcb_timeout(rcb_t *rcb, long elapsed)
{
    assert(rcb);
    if(elapsed < rcb->left_time)
    {
        rcb->left_time -= elapsed;
        return 0;
    }
    else
    {
        return 1;
    }
}

void remove_rspd_get(rcb_t *rcb)
{
    if(rcb->pd_get)
    {
        assert(rcb->pd_get->next == NULL);
        free(rcb->pd_get);
        rcb->pd_get = NULL;
    }
}

/***************** scb ***************************************/

int is_dup_acks(scb_t *scb)
{
    if(scb->in_row_ack_cnt == DUP_ACK_THRESH)
    {
        assert(scb->last_ack_recv == scb->last_pkt_acked);
        
        //dbg_print(5, "dup ack %u\n", scb->last_ack_recv);
        return 1;
    }
    else
        return 0;
}

void update_sliding_win_timer(scb_t *scb, long time_elapsed)
{
    if(scb->state == CNGST_STATE_AVOIDANCE &&
       scb->avoid_time > 0)
    {
        scb->avoid_time -= time_elapsed;
    }
}

// if is_increase if false, ack_num is ignored
void update_sliding_win(scb_t *scb, int is_increase, uint32_t ack_num,
                        int is_fast_retran) 
{
    if(is_increase)
    {
        assert(ack_num > scb->last_pkt_acked);
        scb->last_pkt_acked = ack_num;
        
        if(scb->last_pkt_sent < ack_num)
        {
            scb->last_pkt_sent = ack_num;
        }

        if(scb->state == CNGST_STATE_SLOWSTART)
        {
            scb->win_sz++;
            if(scb->win_sz  == scb->ssthresh)
            {
                scb->state = CNGST_STATE_AVOIDANCE;
            }

            log_winsz(scb->scb_id, scb->win_sz);
        }
        else if(scb->state == CNGST_STATE_AVOIDANCE)
        {
            if(scb->avoid_time <= 0)
            {
                scb->win_sz++;
                scb->avoid_time = AVOIDANCE_TIMEOUT;
               
                log_winsz(scb->scb_id, scb->win_sz);
            }
        }


        dbg_print(1, "sliding window size %u\n", scb->win_sz);
    }
    else // pkt lost, slow start
    {
        scb->ssthresh = max(MIN_SSTHRESH, scb->win_sz / 2); 
        scb->win_sz = INIT_CNGT_WIN_SZ;
        scb->state = CNGST_STATE_SLOWSTART;
        dbg_print(5, "congestion happened, set ssthresh to %u\n",
                  scb->ssthresh);

        if(!is_fast_retran)
        {
           scb->last_pkt_sent = scb->last_pkt_acked + 1; 
        }

        log_winsz(scb->scb_id, scb->win_sz);
    }
}

void update_last_ack_recv(scb_t *scb, uint32_t ack_num)
{
    if(ack_num == scb->last_ack_recv)
    {
        scb->in_row_ack_cnt++;
    }
    else
    {
        scb->last_ack_recv = ack_num;
        scb->in_row_ack_cnt = 1;
    }
}

int is_valid_ack_num(scb_t *scb, uint32_t ack_num)
{
    if(scb->last_pkt_acked <= ack_num && ack_num <= scb->max_pkt_sent)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

inline size_t get_offset_by_pktnum(size_t seq_num, size_t buf_sz)
{
    return seq_num * buf_sz;
}

// buff size no more than MAX_PAYLOAD_SIZE
size_t get_next_pkt_data(char *buff, size_t buf_sz, scb_t *scb)
{
    size_t sd_sz = 0;
    size_t left_sz;
   
    scb->next_byte = scb->start_byte + get_offset_by_pktnum(scb->last_pkt_sent, buf_sz);  

    if(scb->end_delim <= scb->next_byte)  // no more data to send
    {
        return 0;
    }

    if(scb->last_pkt_sent 
       < scb->last_pkt_acked + scb->win_sz) //have window slot
    {
        left_sz = scb->end_delim - scb->next_byte;
        sd_sz = left_sz > buf_sz ? buf_sz : left_sz;
        pread(g_bt_inf.mst_data_fd, buff, sd_sz, scb->next_byte);
        //perror("read failed?");
        scb->next_byte += sd_sz;
        scb->last_pkt_sent++;
        scb->max_pkt_sent = max(scb->max_pkt_sent, scb->last_pkt_sent); 
    }

    return sd_sz;
}

void rollback_last_pkt_send(scb_t *scb, size_t sd_sz)
{
    scb->next_byte -= sd_sz;
    scb->last_pkt_sent--;
}

void reset_scb_timeout(scb_t *scb)
{
    assert(scb);
    scb->left_time = SCB_TIMEOUT;
}

int is_scb_timeout(scb_t *scb, long elapsed)
{
    assert(scb);
    if(elapsed < scb->left_time)
    {
        scb->left_time -= elapsed;
        return 0;
    }
    else
    {
        return 1;
    }
}

scb_t *create_scb(uint32_t chk_id)
{
    scb_t *p;
    p = malloc(sizeof(scb_t));
    if(!p)
        return NULL;
    bzero(p, sizeof(scb_t));

    p->scb_id = scb_id++;

    p->seq_num = 1;
    p->start_byte = chk_id * BT_CHUNK_SIZE;
    p->end_delim = p->start_byte + BT_CHUNK_SIZE;

    p->left_time = SCB_TIMEOUT;

    p->last_ack_recv = 0;
    p->in_row_ack_cnt = 0;

    p->state = CNGST_STATE_SLOWSTART;
    p->avoid_time = AVOIDANCE_TIMEOUT;
    p->ssthresh = INIT_SSTHRESH;
    p->win_sz = INIT_CNGT_WIN_SZ;
    p->last_pkt_acked = 0;
    p->last_pkt_sent = 0;
    p->max_pkt_sent = 0;

    p->pd_pkt_head = NULL;

    return p;

}

void destroy_scb(scb_t *scb)
{
    assert(scb);
    pd_pkt_t *p;

    p = scb->pd_pkt_head;
    while(p)
    {
        scb->pd_pkt_head = p->next;

        free(p);
        p = scb->pd_pkt_head;
    }

    free(scb);
}

int is_sending_finish(scb_t *scb)
{
    if(scb->next_byte >= scb->end_delim && 
       scb->last_pkt_acked == scb->max_pkt_sent)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

pd_pkt_t *detach_next_unresp_pkt(scb_t *scb)
{
    pd_pkt_t *p; 

    if(!(p = scb->pd_pkt_head))
        return NULL;

    scb->pd_pkt_head = scb->pd_pkt_head->next;
    if(scb->pd_pkt_head)
    {
        scb->pd_pkt_head->left_time += p->left_time;
    }

    p->next = NULL;
    
    return p;
}

pd_pkt_t *detach_unresp_pkt_by_seqnum(scb_t *scb, uint32_t seq_num)
{
    pd_pkt_t *p = NULL; 
    pd_pkt_t *pkt = NULL;
    
    p = scb->pd_pkt_head;

    while(p)
    {
        scb->pd_pkt_head = scb->pd_pkt_head->next;
        if(seq_num != p->seq_num)
        {
            free(p);
        }
        else
        {
            assert(pkt == NULL);
            pkt = p;
            pkt->next = NULL;
        }
        p = scb->pd_pkt_head;
    }
    
    return pkt;
}

void add_unresp_pkt(scb_t *scb, pd_pkt_t *pkt)
{
    assert(pkt->next == NULL);

    long time = 0;
    pd_pkt_t *p = scb->pd_pkt_head;
    pd_pkt_t *pre = NULL;
    dbg_print(1, "in add uresp pkt, pkt seq_num is %u, left time is %ld\n",     
                 pkt->seq_num, pkt->left_time);

    while(p && ((time + p->left_time) <= pkt->left_time))
    {
        time += p->left_time;
        pre = p;
        p = p->next;
    }
       
    pkt->next = p; 

    if(pre)
    {
        pre->next = pkt;
    }
    else
    {
        scb->pd_pkt_head = pkt;
    }

    if(p)  // pkt is not end
    {
        p->left_time = p->left_time + time - pkt->left_time;
    }
    
    pkt->left_time = pkt->left_time - time;
    
}

void pkt_check(scb_t *scb, uint32_t ack_num)
{
    pd_pkt_t *p = scb->pd_pkt_head; 
    dbg_print(5, "after remove ack_num %u pkts, the unresp pkt left\n", ack_num);
    while(p)
    {
        dbg_print(5, "seq num is %u, left_time is %ld\n", p->seq_num, p->left_time);
        p = p->next;
    }
}

// remove the acked pkt
void remove_respd_pkt(scb_t *scb, int pkt_type, uint32_t ack_num)
{
    pd_pkt_t *p = scb->pd_pkt_head; 
    pd_pkt_t *pre = NULL;
    pd_pkt_t *tmp;

    while(p)
    {
        if(pkt_type == p->type)
        {
            if(pkt_type != PRO_TYPE_DATA || p->seq_num <= ack_num)
            {
                if(NULL == pre)  // p is the head
                {
                    scb->pd_pkt_head = p->next;
                }
                else
                {
                    pre->next = p->next;
                }

                if(scb->pd_pkt_head == p)  // p is the tail
                {
                    scb->pd_pkt_head = pre;
                }

                tmp = p->next;
                if(tmp)
                {
                    tmp->left_time += p->left_time;
                }
                free(p);
                p = tmp; 

                continue;
            }
        }

        pre = p;
        p = p->next;
    }
    pkt_check(scb, ack_num);
}

pd_pkt_t *get_timeout_pkt(scb_t *scb, long time_elapsed)
{
    assert(scb);
    pd_pkt_t *p = scb->pd_pkt_head;
    pd_pkt_t *tmp = NULL;
    if(!p)
        return NULL;

    if(time_elapsed < p->left_time)
    {
        p->left_time -= time_elapsed;
        return NULL;
    }
    else //time_elapsed >= p->left_time
    {
        tmp = p->next;
        while(tmp)
        {
            scb->pd_pkt_head = tmp->next;
            free(tmp);
            tmp = scb->pd_pkt_head;
        }
        scb->pd_pkt_head = NULL;
        p->next = NULL;
        return p;
    }
}

pd_pkt_t *get_timeout_pkts(scb_t *scb, long time_elapsed)
{
    assert(scb);
    pd_pkt_t *p = scb->pd_pkt_head;
    pd_pkt_t *out_head = NULL;
    pd_pkt_t *out_tail = NULL;
    
    while(p)
    {
        if(time_elapsed < p->left_time)
        {
            p->left_time -= time_elapsed;
            break;
        }
        else //time_elapsed >= p->left_time
        {
            
            time_elapsed -= p->left_time;
            scb->pd_pkt_head = p->next;

            if(!out_head)
            {
                out_head = p;
                out_tail = p;
            }
            else
            {
                out_tail->next = p;
                out_tail = p;
            }

            out_tail->next = NULL;

        }

        p = scb->pd_pkt_head;
    }
 
    return out_head; 
}
