/*
 * peer.c
 *
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "config.h"
#include "sel_ctrl.h"
#include "bt_info.h"
#include "dbg_helper.h"
#include "winsz_logger.h"


void peer_run(bt_config_t *config);
bt_config_t g_config;

int main(int argc, char **argv) {
    int mst_data_fd = -1;
    bt_init(&g_config, argc, argv);
    
    init_winsz_logger();

   // DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
    g_config.identity = 1; // your group number here
    strcpy(g_config.chunk_file, "chunkfile");
    strcpy(g_config.has_chunk_file, "haschunks");
#endif

    bt_parse_command_line(&g_config);

    if(-1 == init_mst_chk_map(g_config.chunk_file, &mst_data_fd))
    {
        goto err;
    }

    if(-1 == init_has_chk_map(g_config.has_chunk_file))
    {
        goto err;
    }

    init_bt_info(mst_data_fd);

    peer_run(&g_config);
    return 0;

err:
    fprintf(stderr, "Error\n");
    return -1;
}

void peer_run(bt_config_t *config)
{
#define TIMER_INTERVAL 1000000
    int sock;
    struct sockaddr_in myaddr;
    fd_set rdset;
    fd_set tmp_rdset;
    fd_set wrset;
    fd_set tmp_wrset;
    bt_peer_t *peer = NULL;

    struct timeval interval;
    struct timeval lefttime;
    interval.tv_sec = 0;
    interval.tv_usec = TIMER_INTERVAL;

    struct user_iobuf *userbuf;

    if ((userbuf = create_userbuf()) == NULL)
    {
        perror("peer_run could not allocate userbuf");
        exit(-1);
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
    {
        perror("peer_run could not create socket");
        exit(-1);
    }

    peer = get_peer_byid(config->peers, config->identity);
    assert(peer);
    myaddr = peer->addr; 

    if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1)
    {
        perror("peer_run could not bind socket");
        exit(-1);
    }

    spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));
    FD_ZERO(&rdset);
    FD_SET(STDIN_FILENO, &rdset);
    FD_SET(sock, &rdset);

    FD_ZERO(&wrset);

    while (1)
    {
        int nfds;
        tmp_rdset = rdset;
        tmp_wrset = wrset;
        lefttime = interval;
   
        nfds = select(sock+1, &tmp_rdset, &tmp_wrset, NULL, &lefttime);
        
        if (nfds >= 0)
        {
            if(bt_process_timeout(interval.tv_usec - lefttime.tv_usec))
            {
                FD_SET(sock, &wrset);
            }
        }
        
        if (nfds > 0)
        {
            if (FD_ISSET(STDIN_FILENO, &tmp_rdset))
            {
                process_user_input(STDIN_FILENO, userbuf, handle_user_input, 
                                   "Currently unused");
                FD_SET(sock, &wrset);
            
            }
            
            send_pd_pkt(sock);
            FD_CLR(sock, &wrset);

            if (FD_ISSET(sock, &tmp_rdset)) 
            {
                if(process_inbound_udp(sock))
                {
                    FD_SET(sock, &wrset);
                }

            }

        }

        if(nfds >= 0)
        {
        
            if(need_sched())
            {
                dbg_print(1, "schedule task\n");
                bt_download_schedule();
                FD_SET(sock, &wrset);
            }
        }
        else
        {
            perror("select err");
            assert(0);
        }
    }
}
