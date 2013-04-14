#ifndef _HELPER_H_
#define _HELPER_H_

static inline int is_same_addr(struct sockaddr_in src_addr, struct sockaddr_in dest_addr)
{
    if(src_addr.sin_family == dest_addr.sin_family &&
       src_addr.sin_port == dest_addr.sin_port &&
       src_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr)
    {
         return 1;
    }
    else
    {
        return 0;
    }
}

static inline uint32_t max(uint32_t num1, uint32_t num2)
{
    return num1 > num2 ? num1 : num2;
}

#endif
