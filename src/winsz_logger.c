#include <time.h>
#include <stdio.h>

#include "winsz_logger.h"

static time_t start_time;
static FILE *fp;

void init_winsz_logger()
{
    time(&start_time);
    fp = fopen("problem2-peer.txt", "w");
}


void log_winsz(uint32_t flow_id, uint32_t win_sz)
{
    char buff[50];
    time_t curr_time; 
    int sz;

    if(fp)
    {
        time(&curr_time);    
        sz = sprintf(buff, "f%u\t\%ld\t%u\n", flow_id,
                     curr_time - start_time, win_sz);
        if(sz <= 0)
        {
            fprintf(stderr, "log error\n"); 
            return ;
        }
        fwrite(buff, 1, sz, fp); 
        fflush(fp);
    }
}


