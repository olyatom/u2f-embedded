#include <stdio.h>

#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "u2f.h"

SHA256_CTX sha256;
char digest[SHA256_DIGEST_LENGTH];

struct keypair
{
    EC_KEY * key;
    uint32_t handle;
} keypairs[10];


void u2f_response_writeback(uint8_t * buf, uint8_t len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%x", (int)*(buf+i));
    }
}

void u2f_response_flush()
{
    printf("\n");
    fflush(stdout);
}

void u2f_response_start()
{
    // nothing needs to be done
}

int8_t u2f_get_user_feedback() { return 0; }


void u2f_sha256_start()
{
    SHA256_Init(&sha256);
}

void u2f_sha256_update(uint8_t * buf, uint8_t len)
{
    SHA256_Update(&sha256, buf, len);
}


void u2f_sha256_finish(uint8_t * buf, uint8_t len)
{
    if (buf && len)
    {
        SHA256_Update(&sha256, buf, len);
    }
    SHA256_Final(digest, &sha256);
}

void u2f_ecdsa_sign(uint8_t * dest, uint8_t * handle)
{
    uint32_t h = *(uint32_t*)dest;
    int i = 0;
    int total = sizeof(keypairs) / sizeof(struct keypair);
    for (; i < total; i++)
    {
        if (keypairs[i].handle == h)
        {
            ECDSA_SIG * s = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, keypairs[i].key);
            BN_bn2bin(s->r, dest);
            BN_bn2bin(s->s, dest + 32);
            ECDSA_SIG_free(s);
            return;
        }
    }
    printf("no match for %x\n", h);
}

void u2f_new_keypair(uint8_t * handle, uint8_t * pubkey)
{
    int i = 0;
    int total = sizeof(keypairs) / sizeof(struct keypair);
    for (; i < total; i++)
    {
        if (keypairs[i].key == NULL)
        {
            keypairs[i].key = C_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            keypairs[i].handle = i+1;
            break;
        }
        if (i == total-1)
        {
            printf("out out key memory\n");
            return;
        }
    }
    *((uint32_t*) handle) = i+1;
}

uint8_t * u2f_get_attestation_cert()
{

}

int main()
{
    memset(keypairs, 0, sizeof(keypairs));
    return 0;
}

