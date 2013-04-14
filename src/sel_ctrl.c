#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <assert.h>

#include "dbg_helper.h"
#include "sel_ctrl.h"
#include "bt_info.h"
#include "req.h"
#include "bt_protocol.h"
#include "bt_parse.h"
#include "spiffy.h"


extern bt_info_t g_bt_inf;
extern bt_config_t g_config;

// return 1 if need set wrset
int process_inbound_udp(int sock) 
{
#define BUFLEN 1500 
    struct sockaddr_in from; 
    socklen_t fromlen;
    char buf[BUFLEN];
    bt_header_t *head;
    size_t rcvsz;
    int need_wrset = 0;

    fromlen = sizeof(from);
    rcvsz = spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);
   
    //rcvsz = recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);

    if(rcvsz == -1)
    {
        perror("receive failed");
        return need_wrset;
    }
    dbg_print(0, "PROCESS_INBOUND_UDP\nIncoming message from %s:%d\n", 
              inet_ntoa(from.sin_addr), ntohs(from.sin_port));

    head = (bt_header_t *)buf;
    if(!is_valid_pkt_head(head))
    {
        return need_wrset;
    }

    switch(head->type)
    {
    case PRO_TYPE_WHOHAS:
        dbg_print(0, "receive whohas\n");
        process_whohas(buf, from);
        need_wrset = 1;
        break;

    case PRO_TYPE_IHAVE:
        dbg_print(0, "receive ihave\n");
        process_ihave(buf, from);
        break;
    
    case PRO_TYPE_GET:
        dbg_print(0, "receive get\n");
        process_get(buf, from);
        need_wrset = 1;

        break;
    
    case PRO_TYPE_DATA:
        dbg_print(0, "receive data, seq num is %u\n", head->seq_num);
        process_data(buf, from);
        need_wrset = 1;
        
        break;

    case PRO_TYPE_ACK:
        dbg_print(0, "receive ack, ack num is %u\n", head->ack_num);
        process_ack(buf, from);
        need_wrset = 1;
        break;

    case PRO_TYPE_DENIED:
        dbg_print(0, "receive denied\n");

        break;
    
    default: //ginore the pkt
        dbg_print(0, "receive unkown type %d\n", head->type);
        break;
    } 

    return need_wrset;
}

int process_user_get(char *chunkfile, char *outputfile)
{
    if(0 != bt_open_wrfile(outputfile))
    {
        printf("Can't open output file \"%s\"\n", outputfile);
        return -1;
    }
    
    assert(NULL == g_bt_inf.pd_rcb_head);
    if(0 != bt_process_user_req(chunkfile))
    {
        printf("Failed to load get-chunks from file \"%s\"\n", chunkfile);
        bt_close_wrfile(); 
        return -1;
    }

    printf("Start downloading...\n");

    return 0;
}

// 0 for valid user requset
// -1 for failure
int handle_user_input(char *line, void *cbdata)
{
    char chunkf[128], outf[128];

    bzero(chunkf, sizeof(chunkf));
    bzero(outf, sizeof(outf));
#ifdef DEBUG
    //strcpy(line, "GET ../test/B.chunks /tmp/a.tmp");
#endif
    if (sscanf(line, "GET %120s %120s", chunkf, outf))
    {
        if(bt_is_downloading()) // still downloading, ignore request
        {
            printf("Still downloading... Don't type in\n");
            return -1;
        }

        if (strlen(outf) > 0)
        {
            return process_user_get(chunkf, outf);
        }
    }
    

    printf("Invalid input\n");
    printf("Usage: GET <get_chunk_file> <out_put_file>\n");

    return -1;
}


