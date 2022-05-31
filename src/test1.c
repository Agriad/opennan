#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <pcap/pcap.h>

int main() {
    // char pcap_errbuf[PCAP_ERRBUF_SIZE];
    // pcap_errbuf[0]='\0';
    // char* if_name = "wlx00c0caae6579";

    // pcap_t* pcap=pcap_open_live(if_name,96,0,0,pcap_errbuf);
    // printf("here1\n");
    // if (pcap_errbuf[0]!='\0') {
    //     fprintf(stderr,"%s",pcap_errbuf);
    // }
    // printf("here2\n");
    // if (!pcap) {
    //     exit(1);
    // }

    // service test crashing message
    // uint8_t own_buffer[] = {
    //     0x00,
    //     0x03,
    //     0x03,
    //     0x23,
    //     0x00,
    //     0x06,
    //     0x02,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0xd0,
    //     0x18,
    //     0x00,
    //     0x00,
    //     0x04,
    //     0x00,
    //     0x00,
    //     0x0b,
    //     0x00,
    //     0x00,
    //     0x80,
    //     0x02,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0xd0,
    //     0x00,
    //     0x3a,
    //     0x01,
    //     0x02,
    //     0x1f,
    //     0x7a,
    //     0xa6,
    //     0xa8,
    //     0xd3,
    //     0x00,
    //     0xc0,
    //     0xca,
    //     0xae,
    //     0x65,
    //     0x79,
    //     0x50,
    //     0x6f,
    //     0x9a,
    //     0x01,
    //     0x1b,
    //     0xa0,
    //     0x70,
    //     0x03,
    //     0x04,
    //     0x09,
    //     0x50,
    //     0x6f,
    //     0x9a,
    //     0x13,
    //     0x03,
    //     0x16,
    //     0x00,
    //     0x9f,
    //     0x20,
    //     0x77,
    //     0x6f,
    //     0x72,
    //     0x6c,
    //     0x64,
    //     0x21,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00,
    //     0x00
    // };

    uint8_t own_buffer[] = {
        0x00, 
        0x00,
        0x0b,
        0x00,
        0x26,
        0x00,
        0x00,
        0x00,
        0x10,
        0x02,
        0xc8,
        0x80,
        0x00,
        0x00,
        0x00,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0x00,
        0xc0,
        0xca,
        0xae,
        0x65,
        0x79,
        0x50,
        0x6f,
        0x9a,
        0x01,
        0x78,
        0x1d,
        0x00,
        0x01,
        0xff,
        0xff,
        0x23,
        0x71,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x20,
        0x04,
        0xff,
        0x19,
        0x50,
        0x6f,
        0x9a,
        0x13,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x01,
        0x0d,
        0x00,
        0x00,
        0xc0,
        0xca,
        0xae,
        0x65,
        0x79,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xb7,
        0x94,
        0x64,
        0x75,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12,
        0x12
    };

    own_buffer[35] = 0x12;
    own_buffer[36] = 0x12;
    own_buffer[37] = 0x12;
    own_buffer[38] = 0x12;
    own_buffer[39] = 0x12;
    own_buffer[40] = 0x12;
    own_buffer[41] = 0x12;
    own_buffer[42] = 0x12;
    own_buffer[43] = 0x12;

    unsigned char *hash = HMAC(EVP_sha256(), 
        "example_key", 
        strlen("example_key"), 
        own_buffer, 
        64,
        NULL,
        NULL);

    printf("wlan send: hash length - %ld\n", sizeof(hash) / sizeof(hash[0]));

    // if (pcap_inject(pcap,&own_buffer,sizeof(own_buffer))==-1) {
    //     pcap_perror(pcap,0);
    //     pcap_close(pcap);
    //     exit(1);

    //     pcap_close(pcap);
    // }

    printf("here3\n");

    // uint8_t* req[] = {0x12, 0x12, 0x12};

    // if (pcap_inject(pcap,&req,sizeof(req))==-1) {
    //     pcap_perror(pcap,0);
    //     pcap_close(pcap);
    //     exit(1);

    //     pcap_close(pcap);
    // }
}

/*

gcc test1.c -o test1 -lpcap -lev -I/usr/include/libnl3 $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0 libnl-route-3.0 openssl)

*/