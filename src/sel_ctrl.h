#ifndef _SEL_CTRL_H_
#define _SEL_CTRL_H_


int process_inbound_udp(int sock);

int handle_user_input(char *line, void *cbdata);
int process_user_req();
#endif
