#ifndef _PEER_INFO_H_
#define _PEER_INFO_H_

#include "req.h"


typedef enum _PEER_STATE
{
    PEER_STATE_NO_DOWNLOADING = 0,
    PEER_STATE_DOWNLOADING
} PEER_STATE;

typedef struct bt_peer_s 
{
  short  id;
  struct sockaddr_in addr;

  PEER_STATE state;
  rcb_t *rcb;

  scb_t *scb;
  
  struct bt_peer_s *next;
} bt_peer_t;

short get_peer_id(bt_peer_t *head, struct sockaddr_in addr);
bt_peer_t *get_peer_byaddr(bt_peer_t *head, struct sockaddr_in addr);
bt_peer_t *get_peer_byid(bt_peer_t *head, short id);

void clean_peer_download(bt_peer_t *peer);
void clean_peer_sending(bt_peer_t *peer);


#endif
