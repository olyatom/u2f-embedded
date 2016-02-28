#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

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
EVP_PKEY * attestkey = NULL;

static void die()
{
    fprintf(stderr,"signature error: %s\n",
            ERR_error_string(ERR_get_error(),NULL) );
    exit(1);
}


void u2f_response_writeback(uint8_t * buf, uint8_t len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%02x", (int)*(buf+i));
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
    uint32_t h = *(uint32_t*)handle;
    int i = 0;
    int total = sizeof(keypairs) / sizeof(struct keypair);
    if (h == *(uint32_t*)U2F_ATTESTATION_HANDLE)
    {
        EC_KEY * ak = EVP_PKEY_get1_EC_KEY(attestkey);
        ECDSA_SIG * s = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, ak);
        if (s==NULL){die();}

        
        BN_bn2bin(s->r, dest);
        BN_bn2bin(s->s, dest + 32);

        ECDSA_SIG_free(s);
        return;
    }
    for (; i < total; i++)
    {
        if (keypairs[i].handle == h)
        {
            ECDSA_SIG * s = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, keypairs[i].key);
            if (s==NULL){die();}
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
            keypairs[i].key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            EC_KEY_generate_key(keypairs[i].key);
            keypairs[i].handle = i+1;
            const EC_POINT * pt = EC_KEY_get0_public_key(keypairs[i].key);
            BIGNUM x, y;
            BN_init(&x);
            BN_init(&y);
            EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(keypairs[i].key),
                pt, &x, &y, NULL);
            assert(BN_bn2bin(&x,pubkey)==32);
            assert(BN_bn2bin(&y,pubkey+32)==32);
            BN_free(&x);
            BN_free(&y);
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
    return 
"\n\x06\x08*\x86H\xce=\x04\x03\x020E1\x0b0\t\x06\x03U\x04\x06\x13\x02AU1\x130\x11"
"U1\x130\x11\x06\x03U\x04\x08\x0c\nSome-State1!0\x1f\x06\x03U\x04"
"\x1f\x06\x03U\x04\n\x0c\x18Internet Widgits Pty L"
"Pty Ltd0\x1e\x17\r160227161305Z\x17\r2202"
"\r220225161305Z0E1\x0b0\t\x06\x03U\x04\x06\x13\x02AU1"
"\x13\x02AU1\x130\x11\x06\x03U\x04\x08\x0c\nSome-State1!0\x1f\x06"
"1!0\x1f\x06\x03U\x04\n\x0c\x18Internet Widgits Pt"
"ts Pty Ltd0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce="
"*\x86H\xce=\x03\x01\x07\x03B\x00\x046\xd9\x9a\xc6\xa8\xda\x88U\x18\x85\x8c\xed\xad\xe5Q\xe0xv"
"\xe5Q\xe0xv\xc0\x1c\x19\xe8\xe8\xdf\xde\xee\xd1-\x8c\x8f\xad\\R\xa7^tR\x9aeE\xf8i\xfc"
"eE\xf8i\xfc\xe8\x8c\x0cB\xd7\x1e*xT\x08a\x19\x01\x00\x1bw`\x8a\x92\x8a)0\n\x06\x08"
")0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\x000E\x02!\x00\xc5\xa9\'\xa6\xf3\x06\xee\xbd\xd5"
"\xf3\x06\xee\xbd\xd5\xbeG\xe8R\xc47c\xd4\xc0\x01\x86\xbc\xd0\x87\xe9TvN\x81l\xd7Vr\x02 "
"\xd7Vr\x02 vw$\x93\x98\xc0\x0e\r>\xfdn\x01VBV\xec\xcf\xba\x8a\xa5l^(Q7"
"l^(Q7\x8dU\xf4\r\x12X\x9d";
}

int main(int argc, char * argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <privkey>\n",argv[0]);
        return 1;
    }
    uint8_t buf[5000];
    memset(keypairs, 0, sizeof(keypairs));
    ERR_load_crypto_strings();   

    FILE * f = fopen(argv[1], "r");
    if (f==NULL)
    {
        perror("fopen");
        return 1;
    }
    if(!PEM_read_PrivateKey(f, &attestkey, NULL, NULL))
    {
        die();
    }

    read(fileno(stdin), buf, sizeof(buf));

    u2f_request((struct u2f_request_apdu *) buf);
    fclose(f);
    ERR_free_strings();
    return 0;
}

