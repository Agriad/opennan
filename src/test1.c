#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <pcap/pcap.h>

int main() {
    uint64_t first = 0x1122334455667788;
    uint8_t *second = &first;
    uint32_t third;

    memcpy(&third, second, sizeof(uint32_t));

    printf("third: %x", third);
}

/*

gcc test1.c -o test1 -lpcap -lev -I/usr/include/libnl3 $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0 libnl-route-3.0 openssl)

*/