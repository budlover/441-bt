#include "peer_info.h"
#include "helper.h"

short get_peer_id(bt_peer_t *head, struct sockaddr_in addr)
{
    bt_peer_t *p;
    p = head;

    while(p)
    {
        if(is_same_addr(p->addr, addr))
        {
            return p->id;
        } 
        p = p->next;
    }
    
    return -1; 
}

bt_peer_t *get_peer_byaddr(bt_peer_t *head, struct sockaddr_in addr)
{
    bt_peer_t *p;
    p = head;

    while(p)
    {
        if(is_same_addr(p->addr, addr))
        {
            return p;
        } 
        p = p->next;
    }
    
    return NULL;
}

bt_peer_t *get_peer_byid(bt_peer_t *head, short id)
{
    bt_peer_t *p;
    p = head;

    while(p)
    {
        if(id == p->id)
        {
            return p;
        } 
        p = p->next;
    }
    
    return NULL;
}

void clean_peer_download(bt_peer_t *peer)
{
    if(peer->rcb) // tcb may not exist here due to reschedule
        destroy_single_rcb(peer->rcb); 

    peer->rcb = NULL;
    peer->state = PEER_STATE_NO_DOWNLOADING;
}

void clean_peer_sending(bt_peer_t *peer)
{
    destroy_scb(peer->scb);
    peer->scb = NULL;
}
