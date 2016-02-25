
#include <stdio.h>

#include "u2f.h"


void u2f_response_writeback(uint8_t * buf, uint8_t len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%x", (int)*(buf+i));
    }
    printf("\n");
}


int main()
{
    
    return 0;
}

