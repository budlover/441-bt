#include "dbg_helper.h"

#include <stdlib.h>
#include <stdio.h>

int dbg_level = INT_MAX;

/*
   this function can be used for debug and log
 */
void __dbg_print(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); 
    va_end(ap);

    fflush(stderr);
}


void dbg_init(int level)
{
    dbg_level = level;
}
