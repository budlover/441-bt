#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>

#include "dbg_helper.h"
#include "req.h"
#include "bt_info.h"
#include "bt_parse.h"
#include "bt_protocol.h"
#include "helper.h"
#include "spiffy.h"

bt_info_t g_bt_inf;
extern bt_config_t g_config;

static void append_pd_pkt(pd_pkt_t *pd_pkt);
static void insert_pd_pkt(pd_pkt_t *pd_pkt);

// retransmited packet has the priority to be sent ahead of others
static void bt_prep_retran(scb_t *scb)
{
    pd_pkt_t *p = NULL;
    
    if((p = detach_unresp_pkt_by_seqnum(scb, scb->last_pkt_acked + 1)))
    {
       insert_pd_pkt(p);
    }
}

// prepare a whohas packet that only query for a single hash
void bt_prep_single_whohas(rcb_t *rcb)
{
    bt_peer_t *peer;
    peer = g_config.peers;
    hash_set_t set;
    size_t pl_sz; //payload size
    pd_pkt_t *new_pkt;

    set.cnt = 1;
    memcpy(set.hash[0].hash, rcb->chk_map->hash, SHA1_HASH_SIZE);
    set.next = NULL;

    while(peer)
    {
        // skip self
        if(peer->id == g_config.identity)
        {
            peer = peer->next;
            continue; 
        }
     
        pl_sz = calc_whohas_size(set.cnt);
        new_pkt = new_pd_pkt(pl_sz, peer->addr, PRO_TYPE_WHOHAS, 0);
        if(!new_pkt)
            return;

        // get payload
        fill_whohas(new_pkt->payload, &set);

        // insert to peding pkt queue
        append_pd_pkt(new_pkt);
    
        peer = peer->next;
    }
}

// prepare a whohas packet that query chunks from a set of hash value
void bt_prep_whohas(hash_set_t *sethead)
{
    bt_peer_t *peer;
    hash_set_t *reqset = NULL;
    pd_pkt_t *new_pkt;

    size_t pl_sz; //payload size

    assert(g_bt_inf.pd_pkt_head == NULL);
    peer = g_config.peers;
    while(peer)
    {
        // skip self
        if(peer->id == g_config.identity)
        {
            peer = peer->next;
            continue; 
        }
     
        reqset = sethead;
        while(reqset)
        {
            pl_sz = calc_whohas_size(reqset->cnt);
            new_pkt = new_pd_pkt(pl_sz, peer->addr, PRO_TYPE_WHOHAS, 0);
            if(!new_pkt)
                return;
 
            // get payload
            fill_whohas(new_pkt->payload, reqset);

            // insert to peding pkt queue
            append_pd_pkt(new_pkt);

            reqset = reqset->next;
        } 
    
        peer = peer->next;
    } 
}

void bt_prep_ihave(hash_set_t *haveset, struct sockaddr_in addr)
{
    size_t pl_sz;
    pd_pkt_t *new_pkt;

    assert(haveset->next == NULL); // should only have one have set

    pl_sz = calc_ihave_size(haveset->cnt);
    new_pkt = new_pd_pkt(pl_sz, addr, PRO_TYPE_IHAVE, 0);
    if(!new_pkt)
        return;

    // get payload
    fill_ihave(new_pkt->payload, haveset);

    // insert to pending pkt queue
    append_pd_pkt(new_pkt);
}

int bt_prep_denied(struct sockaddr_in addr)
{
    pd_pkt_t *new_pkt;
    size_t pl_sz;

    pl_sz = calc_get_size();
    new_pkt = new_pd_pkt(pl_sz, addr, PRO_TYPE_DENIED, 0);
    if(!new_pkt)
        return -1;
    fill_denied(new_pkt->payload);
    
    // insert to pending pkt queue
    append_pd_pkt(new_pkt);
    
    return 0;    
}


int bt_prep_get(uint8_t *hash, struct sockaddr_in addr)
{
    pd_pkt_t *new_pkt;
    size_t pl_sz;

    pl_sz = calc_get_size();
    new_pkt = new_pd_pkt(pl_sz, addr, PRO_TYPE_GET, 0);
    if(!new_pkt)
        return -1;
    fill_get(new_pkt->payload, hash);
    
    // insert to pending pkt queue
    append_pd_pkt(new_pkt);
    
    return 0;    
}

int bt_prep_data(scb_t *scb, struct sockaddr_in addr)
{
#define MAX_DATA_PAYLOAD_SIZE 1400
    static char buff[MAX_DATA_PAYLOAD_SIZE];
    pd_pkt_t *new_pkt;
    size_t sd_sz=0;
    size_t pl_sz;

    while(0 != (sd_sz = get_next_pkt_data(buff, MAX_DATA_PAYLOAD_SIZE, scb)))
    {
        pl_sz = calc_data_size(sd_sz);
        new_pkt = new_pd_pkt(pl_sz, addr, PRO_TYPE_DATA, 
                             scb->last_pkt_sent);
        if(!new_pkt)
        {
            rollback_last_pkt_send(scb, sd_sz);
            return -1;
        }
        
        fill_data(new_pkt->payload, buff, sd_sz, scb->last_pkt_sent);
        // insert to pending pkt queue
        append_pd_pkt(new_pkt);
    }
    
    return 0;
}

int bt_prep_ack(uint32_t seq_num, struct sockaddr_in addr)
{

    pd_pkt_t *new_pkt;
    size_t pl_sz;

    pl_sz = calc_ack_size();
    new_pkt = new_pd_pkt(pl_sz, addr, PRO_TYPE_ACK, 0);
    if(!new_pkt)
        return -1;
    fill_ack(new_pkt->payload, seq_num);

    // insert to pending pkt queue
    append_pd_pkt(new_pkt);


    return 0;
}

int init_bt_info(int mst_data_fd)
{
    bzero(&g_bt_inf, sizeof(bt_info_t));
    g_bt_inf.wrfile_fd = -1;
    g_bt_inf.need_sched = NO_SCHED;
    g_bt_inf.mst_data_fd = mst_data_fd;

    return 0;
}

// open the file to write to after download
int bt_open_wrfile(const char* wrfile)
{
    int fd;
    fd = open(wrfile, O_WRONLY | O_CREAT, S_IRWXU);

    if(-1 != fd)
    {
        g_bt_inf.wrfile_fd = fd;
        return 0;
    }
    else
    {
        return -1;
    }
}

void bt_close_wrfile()
{
    if(-1 == g_bt_inf.wrfile_fd)
    {
        close(g_bt_inf.wrfile_fd);
        g_bt_inf.wrfile_fd = -1;
    }
}

void send_pd_pkt(int sock)
{
    pd_pkt_t *to_snd_pkt;
    bt_peer_t *p = NULL;
    socklen_t sklen = sizeof(struct sockaddr_in); 

    to_snd_pkt = g_bt_inf.pd_pkt_head;
    while(to_snd_pkt)
    {
        int tmp;
/*
        tmp = sendto(sock, to_snd_pkt->payload, to_snd_pkt->pl_sz, 
                     MSG_DONTWAIT, (struct sockaddr *)&to_snd_pkt->addr,
                     sklen);
*/

        tmp = spiffy_sendto(sock, to_snd_pkt->payload, to_snd_pkt->pl_sz, 
                     MSG_DONTWAIT, (struct sockaddr *)&to_snd_pkt->addr,
                     sklen);

        
        if(-1 == tmp)
        {
            perror("send failed");
        }
        
        g_bt_inf.pd_pkt_head = to_snd_pkt->next;
        to_snd_pkt->next = NULL;

        if(to_snd_pkt->type == PRO_TYPE_GET)
        {
            p = get_peer_byaddr(g_config.peers, to_snd_pkt->addr);
            assert(p);
            assert(p->rcb);
            reset_left_time(to_snd_pkt);
            add_unresp_get(p->rcb, to_snd_pkt);
        }
        else if(to_snd_pkt->type == PRO_TYPE_DATA)
        {
            p = get_peer_byaddr(g_config.peers, to_snd_pkt->addr);
            assert(p);
            assert(p->scb);
            
            reset_left_time(to_snd_pkt);
            add_unresp_pkt(p->scb, to_snd_pkt);
        }
        else
        {
            free(to_snd_pkt);
        }

        to_snd_pkt = g_bt_inf.pd_pkt_head;
    }
    g_bt_inf.pd_pkt_tail = NULL;

}

int need_sched()
{
    return g_bt_inf.need_sched;
}

// return 1 if there is some task to download
// return 0 if not
int bt_download_schedule()
{
    rcb_t *r;
    rcb_t *pre = NULL;
    bt_peer_t *p = NULL;
    darr_t *darr = NULL;
    size_t n;
   
    char *buffer = NULL; 

    r = g_bt_inf.pd_rcb_head;
    
    g_bt_inf.need_sched = NO_SCHED;  // clean the flag

    if(!r && g_bt_inf.curr_in_cnn == 0) // all task down
    {
        assert(g_bt_inf.wrfile_fd != -1);
        assert(g_bt_inf.pd_rcb_cnt == 0);

        printf("Download finished\n");
        
        close(g_bt_inf.wrfile_fd);
        g_bt_inf.wrfile_fd = -1;

        return 0;
    }

    while(r && g_bt_inf.curr_in_cnn < g_config.max_conn)
    {
        darr = r->have_peers;
        if(darr)
        {
            for(n = 0; n < darr->curr_elem; ++n)
            {
                p = get_peer_byid(g_config.peers, darr->arr[n]);
                assert(p);
                if(p->rcb != NULL)
                {
                    continue;  // is downloading from the peer
                }   
            
                buffer = malloc(BT_CHUNK_SIZE);
                if(!buffer)
                {
                    return 0;
                }

                //detach and reattach the rcb to that peer     
                if(!pre) // first
                {
                    g_bt_inf.pd_rcb_head = r->next;
                }
                else
                {
                    pre->next = r->next;
                }
                p->rcb = r;
                p->state = PEER_STATE_DOWNLOADING;

                r = r->next;          // this two order should not be changed
                p->rcb->next = NULL;

                p->rcb->buffer = buffer;

                memset(p->rcb->buffer, 0, BT_CHUNK_SIZE);

                // update counter info
                g_bt_inf.curr_in_cnn++;
                g_bt_inf.pd_rcb_cnt--;

                bt_prep_get(p->rcb->chk_map->hash, p->addr);
                break;
            } 
        }       
        
        if(!darr || n == darr->curr_elem) // no peer have the file now
        {
            pre = r;
            r = r->next;
        }
        // else don't change pointer, because "r" is retattched
     }

    return 0;
}

void set_need_sched()
{
    g_bt_inf.need_sched = NEED_SCHED;
}

void resched_download(bt_peer_t *peer)
{
    assert(peer->rcb);

    reset_rcb(peer->rcb);
    
    (g_bt_inf.curr_in_cnn)--;

    peer->rcb->next = g_bt_inf.pd_rcb_head;
    g_bt_inf.pd_rcb_head = peer->rcb;
    g_bt_inf.pd_rcb_cnt++;

    peer->rcb = NULL; //keep the order of the two
    clean_peer_download(peer);
}

void bt_finish_download(bt_peer_t *peer)
{
    (g_bt_inf.curr_in_cnn)--;
    clean_peer_download(peer);
}

void bt_finish_sending(bt_peer_t *peer)
{
    (g_bt_inf.curr_out_cnn)--;
    clean_peer_sending(peer);
}

int process_ack(char *buf, struct sockaddr_in addr)
{
    bt_peer_t *peer;
    bt_header_t *head = (bt_header_t *)buf;

    peer = get_peer_byaddr(g_config.peers, addr);
    if(!peer)
        return -1;

    if(!peer->scb)  // no sending data
        return -1;

    // check ack num
    if(!is_valid_ack_num(peer->scb, head->ack_num))
    {
        return -1;
    }
   
    reset_scb_timeout(peer->scb); 

    update_last_ack_recv(peer->scb, head->ack_num);
   
    // check if not duplicated ack 
    if(head->ack_num > peer->scb->last_pkt_acked)
    {

        remove_respd_pkt(peer->scb, PRO_TYPE_DATA, head->ack_num);
        update_sliding_win(peer->scb, ENLARGE_SLIDING_WIN, head->ack_num, 0);
        
        if(is_sending_finish(peer->scb)) // finished send all
        {
            assert(peer->scb->pd_pkt_head == NULL);
            
            dbg_print(1, "all pkt acked, sending finished\n");
            bt_finish_sending(peer);
        }
        else
        {
            bt_prep_data(peer->scb, addr);
        } 
    }
    else if(is_dup_acks(peer->scb))
    {
        dbg_print(5, "in row dup ack, need retran\n");
        
        bt_prep_retran(peer->scb);
        update_sliding_win(peer->scb, SHRINK_SLIDING_WIN, 0, 0);
    }
  
    return 0;
}

int process_data(char *buf, struct sockaddr_in addr)
{
    bt_peer_t *peer = NULL;
    recv_pkt_t *new_recv = NULL;
    char *data = NULL;
    size_t pl_sz;
    char hash_str[SHA1_HASH_SIZE * 2 + 1];

    peer = get_peer_byaddr(g_config.peers, addr);
    if(!peer)
        return -1;

    if(!peer->rcb) // not downloading
        return -1;

    assert(peer->rcb->buffer);

    // seq num falls out of window
    if(!is_valid_seq_num(peer->rcb, ((bt_header_t *)buf)->seq_num))
    {
    //    bt_prep_ack(peer->rcb->last_pkt_expt - 1, addr);
        return -1;
    }


    remove_rspd_get(peer->rcb);
    reset_rcb_timeout(peer->rcb);


    data = get_data_payload(buf, &pl_sz);
    new_recv = new_recv_pkt(((bt_header_t *)buf)->seq_num, pl_sz, data);
    if(!new_recv) // can't buffer pkt, should not ack
    {
        return -1;
    }
   
    if(0 != insert_recv_pkt(peer->rcb, new_recv)) 
    {
        // pkt already buffered
        free(new_recv);
        bt_prep_ack(peer->rcb->last_pkt_expt - 1, addr);
        return -1;
    }

    update_last_pkt_expt(peer->rcb);

    // ack should not be sent util expt num updated
    bt_prep_ack(peer->rcb->last_pkt_expt - 1, addr);

    if(read_buf_data(peer->rcb)) // if not 0, have entire chunk
    {
        if(is_consistent_chunk(peer->rcb))
        {
            write_chunk_to_file(peer->rcb);
            add_has_chunk(peer->rcb->chk_map->hash);
            binary2hex(peer->rcb->chk_map->hash, SHA1_HASH_SIZE, hash_str);
            printf("Got chunk %.*s\n", SHA1_HASH_SIZE * 2, hash_str);
            bt_finish_download(peer);
        }
        else // hash doesn't match try to redownload
        {
            resched_download(peer);
        }
        set_need_sched();
    }

    return 0;
}

// if -1 is return, a denial need to be send
int process_get(char *buf, struct sockaddr_in addr)
{
    uint8_t *hash;
    bt_peer_t *peer;
    chunk_map_t *chkm;

    // full connection
    if(g_bt_inf.curr_out_cnn == g_config.max_conn)
        return -1;

    peer = get_peer_byaddr(g_config.peers, addr);
    if(!peer)
        return -1;

    if(peer->scb != NULL) // still servering the one
        return -1;
    
    hash = (uint8_t *)(buf + sizeof(bt_header_t));
    if(!(chkm = do_i_have_chunk(hash)))
        return -1;

    peer->scb = create_scb(chkm->chk_id);
    if(!peer->scb)
        return -1;

    g_bt_inf.curr_out_cnn++;

    bt_prep_data(peer->scb, addr);
    return 0;
}

int process_whohas(char *buf, struct sockaddr_in addr)
{
    uint32_t *cnt;
    hash_v_t *hash;
    hash_set_t *haveset;

    cnt = (uint32_t *)(buf + sizeof(bt_header_t));
    hash = (hash_v_t *)(cnt + 1);
    haveset = get_ihave_hash_set(hash, (int)*cnt);

    if(!haveset)
        return -1;

    bt_prep_ihave(haveset, addr);
    free_hash_sets(haveset);

    return 0;
}

int process_ihave(char *buf, struct sockaddr_in addr)
{
    uint32_t *cnt;
    hash_v_t *hash;
    short id;

    id = get_peer_id(g_config.peers, addr);
    if(-1 == id)
        return -1;   // not from known peer

    cnt = (uint32_t *)(buf + sizeof(bt_header_t));
    hash = (hash_v_t *)(cnt + 1);
    
    update_have_peer(g_bt_inf.pd_rcb_head, hash, (int)*cnt, id);
    
    set_need_sched();
    return 0;
}

int bt_process_user_req(const char *get_chunkfile)
{
    hash_set_t *set_head;
    int cnt = 0;

    g_bt_inf.pd_rcb_head = load_get_chunks(get_chunkfile, &cnt);
    if(g_bt_inf.pd_rcb_head == NULL)
    {
        return -1;
    }
    g_bt_inf.pd_rcb_cnt = cnt;

    set_head = get_req_hash_sets(g_bt_inf.pd_rcb_head, g_bt_inf.pd_rcb_cnt);
    if(!set_head) // get_hash_set failled
    {
        goto err; 
    }
    
    bt_prep_whohas(set_head);
    free_hash_sets(set_head); 

    return 0;

err:
    free_rcbs(g_bt_inf.pd_rcb_head);
    g_bt_inf.pd_rcb_head = NULL;
    g_bt_inf.pd_rcb_cnt = 0;
    return -1;

}

// packet timeout, congestion control
static int bt_process_pd_pkts_timeout(scb_t *scb, long time_elapsed)
{
    pd_pkt_t *pd_pkt = NULL;
    int is_timeout = 0;

    pd_pkt = get_timeout_pkt(scb, time_elapsed);
    if(pd_pkt)
    {
        is_timeout = 1;
       
        pd_pkt->next = NULL;
        append_pd_pkt(pd_pkt);
        dbg_print(3, "pkt seq num %u time out, retran\n", pd_pkt->seq_num);
        
    }

    return is_timeout;
}

// detect requesting peer down
static void bt_process_scb_timeout(bt_peer_t *peer, long time_elapsed)
{
    if(is_scb_timeout(peer->scb, time_elapsed))
    {
        dbg_print(5, "scb time out, peer down\n");
        bt_finish_sending(peer);
    }

}

// detect serving peer down
static int bt_process_get_timeout(rcb_t *rcb, long time_elapsed)
{
    pd_pkt_t *pd_get = NULL;

    pd_get = is_get_timeout(rcb, time_elapsed);
    if(pd_get)
    {
        dbg_print(5, "get time out, retran\n");
        append_pd_pkt(pd_get);
        return 1;
    }
    return 0;
}

// detect serving peer down
static void bt_process_rcb_timeout(bt_peer_t *peer, long time_elapsed)
{
    size_t idx;

    if(is_rcb_timeout(peer->rcb, time_elapsed))
    {
        dbg_print(5, "rcb time out, peer down\n");
       
        assert(peer->rcb->have_peers);
        idx = get_elem_idx(peer->rcb->have_peers, peer->id);
        assert(idx != -1);
        rm_elem_by_idx(peer->rcb->have_peers, idx);

        resched_download(peer);
        set_need_sched();
    } 
}

int bt_process_timeout(long time_elapsed)
{
    bt_peer_t *p;
    int is_timeout = 0;
    rcb_t *rcb = NULL;

    /* process pending request timeout *********************************/
    rcb = g_bt_inf.pd_rcb_head;
    while(rcb)
    {
        if(is_pd_req_timeout(rcb, time_elapsed))
        {
           bt_prep_single_whohas(rcb); 
           is_timeout = 1;
        }

        rcb = rcb->next;
    }
    /* process pending request timeout end ******************************/
   

    p = g_config.peers;
    while(p)
    {
        // skip self 
        if(p->id == g_config.identity)
        {
            p = p->next;
            continue;
        }

        /* process rcb timeouu */
        if(p->rcb)
        {
            bt_process_rcb_timeout(p, time_elapsed);
            // no pkt need send, no need set is_timeout
        }
        
        // need check rcb again, cause rcb timeout may cause it set to NULL
        if(p->rcb)
        {
            if(bt_process_get_timeout(p->rcb, time_elapsed))
            {
                is_timeout = 1;
            }
        }

        /* process scb timeout */
        if(p->scb)
        {
            bt_process_scb_timeout(p, time_elapsed);
            // no pkt need send, no need set is_timeout
        }

        /* process pkt timeout */
        // need check scb again, cause scb timeout may cause it set to NULL
        if(p->scb)
        {
            if(bt_process_pd_pkts_timeout(p->scb, time_elapsed))
            {
                is_timeout = 1;
                update_sliding_win(p->scb, SHRINK_SLIDING_WIN, 0, 0);
            }
        }

        if(p->scb)
        {
            update_sliding_win_timer(p->scb, time_elapsed);
        }
        p = p->next;
    }

    return is_timeout;
}

static void append_pd_pkt(pd_pkt_t *pd_pkt)
{
    pd_pkt_t *head = g_bt_inf.pd_pkt_head;
    pd_pkt_t *tail = g_bt_inf.pd_pkt_tail;
   
    assert(!pd_pkt->next);

    if(!head) // empty queue 
    {
        g_bt_inf.pd_pkt_head = pd_pkt;
    }
    else
    {
        tail->next = pd_pkt;
    }
    g_bt_inf.pd_pkt_tail = pd_pkt;
}

// insert pending packet to the front
static void insert_pd_pkt(pd_pkt_t *pd_pkt)
{
    pd_pkt_t *tail = g_bt_inf.pd_pkt_tail;
   
    assert(!pd_pkt->next);

    if(!tail) // empty queue 
    {
        g_bt_inf.pd_pkt_tail = pd_pkt;
    }
    pd_pkt->next = g_bt_inf.pd_pkt_head;
    g_bt_inf.pd_pkt_head = pd_pkt;
}

// check if still tack not finisehd
int bt_is_downloading()
{

    if(!g_bt_inf.pd_rcb_head && g_bt_inf.curr_in_cnn == 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }

}
