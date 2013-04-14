#ifndef _BT_INFO_H_
#define _BT_INFO_H_
#include <netinet/in.h>
#include "req.h"
#include "bt_parse.h"
#include "bt_protocol.h"
#include "pkts.h"

#define NEED_SCHED 1
#define NO_SCHED 0


typedef struct bt_info
{
    int mst_data_fd;
    int curr_in_cnn;    // current requesting connection count
    int curr_out_cnn;   // current serving connection count
    int wrfile_fd;      // the current out put file descriptor
    
    int pd_rcb_cnt;         // pendign downloading chunk counter
    rcb_t *pd_rcb_head;     // pending downloading chunk list header
    int need_sched;

    pd_pkt_t *pd_pkt_head;     // head of list of packet to send 
    pd_pkt_t *pd_pkt_tail;     // tail of list of packet to send 

} bt_info_t;



int init_bt_info(int mst_data_fd);

int bt_open_wrfile(const char* wrfile);
void bt_close_wrfile();

int bt_is_downloading();
int bt_download_schedule();
void set_need_sched();
void resched_download(bt_peer_t *peer);
int need_sched();
void bt_finish_download(bt_peer_t *peer);

void send_pd_pkt(int sock);

int bt_process_user_req(const char *get_chunkfile);

int process_whohas(char *buf, struct sockaddr_in addr);
int process_ihave(char *buf, struct sockaddr_in addr);
int process_get(char *buf, struct sockaddr_in addr);
int process_data(char *buf, struct sockaddr_in addr);
int process_ack(char *buf, struct sockaddr_in addr);

int bt_process_timeout(long time_elapsed);
#endif
