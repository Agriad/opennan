#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "hmac-test.h"

int main()
{
    char *message = "ab";
    char *example_key = "c";

    unsigned char *hash = HMAC(EVP_sha256(), 
        example_key, 
        strlen(example_key), 
        message, 
        strlen(message),
        NULL,
        NULL);

    printf("message: %s - hash %u\n", message, hash);
    printf("hash length %d\n", strlen(hash));

    for (int i = 0; i < strlen(hash); i++)
    {
        printf("address %d - uint %u - hex %x\n", i, hash[i], hash[i]);
    }

    return 0;
}

// gcc hmac-test.c -o hmac-test -lssl -lcrypto