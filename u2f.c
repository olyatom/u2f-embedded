#include "u2f.h"

#define DEBUG_PC
#ifdef DEBUG_PC
#include <stdio.h>
#else
#define printf(x)
#endif

void u2f_request(struct u2f_request_apdu * req)
{
    switch(req->ins)
    {
        case U2F_REGISTER:
            break;
        case U2F_AUTHENTICATE:
            break;
        case U2F_VERSION:
            break;
        case U2F_VENDER_FIRST:
            break;
        case U2F_VENDER_LAST:
            break;
        default:
            printf("invalid u2f apdu command: %x\n", req->ins);
    }
}


