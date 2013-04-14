#ifndef WINSZ_LOGGER
#define WINSZ_LOGGER

#include <stdint.h>

void init_winsz_logger();

void log_winsz(uint32_t flow_id, uint32_t win_sz);
#endif
