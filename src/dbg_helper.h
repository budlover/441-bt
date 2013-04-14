#ifndef _DBG_HELPER_H
#define _DBG_HELPER_H

#include <stdarg.h>
#include <assert.h>
#include <limits.h>

extern int dbg_level;

void __dbg_print(const char *fmt, ...);

void dbg_init(int dbg_level);
#ifdef DEBUG

#define DBG_LEVEL 10


#define dbg_print(level, fmt, arg...)                                       \
    do {                                                                    \
                                                                            \
        if(level >= dbg_level)                                              \
        {                                                                   \
            __dbg_print(fmt, ##arg);                                         \
/*          fprintf(stderr, "In %s aroud line: %d\n", __FILE__, __LINE__); */ \
        }                                                                   \
    } while(0)

#else

#define dbg_print(fmt, arg...)
#endif

#define ASSERT(x)       \
    do{                 \
        fprintf(stderr, x); \
        assert(0);      \
    }while(0)


#endif
