#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

//convert a string to number
// entire string should be (+/-)digits
int str_to_num(const char *str, int *num)
{
    char *endptr;
    int ret;

    if (NULL == str || NULL == num)
        return -1;
    
    ret = strtol(str, &endptr, 10);
    if (errno == ERANGE)
        return -1;

    if (*str != '\0' && *endptr == '\0') {
        *num = ret;
        return 0;
    }

    return -1;
}

int str_to_uint32(const char *str, uint32_t *num)
{
    char *endptr;
    long long ret;

    if (NULL == str || NULL == num)
        return -1;
    
    ret = strtoll(str, &endptr, 15);
    if (errno == ERANGE)
        return -1;

    if (*str != '\0' && *endptr == '\0')
    {
        if(ret > UINT32_MAX)
        {
            return -1;
        }
        else
        {
            *num = ret;
            return 0;
        }
    }

    return -1;
}


// convert a string to a number, the string may not be of all digtis
// the first non-digit char is allowed to be the deliminator
int str_to_num_by_delim(const char *str, int *num, char delim)
{
    char *endptr;
    int ret;

    if (NULL == str || NULL == num)
        return -1;
    
    ret = strtol(str, &endptr, 10);
    if (errno == ERANGE)
        return -1;

    if (*str != '\0' && (*endptr == '\0' || *endptr == delim)) {
        *num = ret;
        return 0;
    }

    return -1;
}


// binary seacrh a string in the string array given.
// the string array must be in ascending order
int str_match(const char *dest[], int num, const char *src, int max_len)
{
    int low, hi, mid;
    low = 0;
    hi = num - 1;
    int ret;

    while(low <= hi)
    {
        mid = (low + hi) / 2;

        ret = strncmp(dest[mid], src, max_len);

        if(ret < 0)
        {
            low = mid + 1;
            continue;
        }
        else if(ret > 0)
        {
            hi = mid - 1;
            continue;
        }
        else
        {
           return mid;
        }
    }

    return -1;
}
