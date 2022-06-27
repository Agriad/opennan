#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <pcap/pcap.h>

int main() {
    int *a;
    int *b;

    int c[2] = {1, 2};
    a = c;

    // *b = *a;
    // *(&b + 1) = *(&a + 1);

    printf("a 0 %d", *a);
    // printf("b 0 %d", *b);
    // printf("b 1 %d", *(&b + 1));
}

/*

gcc test1.c -o test1 -lpcap -lev -I/usr/include/libnl3 $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0 libnl-route-3.0 openssl)

*/