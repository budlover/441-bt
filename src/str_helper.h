#ifndef _STR_HELPER_H_
#define _STR_HELPER_H_

int str_to_num(const char *str, int *num);
int str_match(const char *dest[], int num, const char *src, int max_len);
int str_to_num_by_delim(const char *str, int *num, char delim);
int str_to_uint32(const char *str, uint32_t *num);

#endif
