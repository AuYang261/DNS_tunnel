
#include <pcap.h>
#include <time.h>

#include <iostream>

#include "headers.h"

void packetHandler(unsigned char* arg, const struct pcap_pkthdr* pkthdr,
                   const unsigned char* packet) {
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t*)&pkthdr->ts.tv_sec));
    iphdr* ip_header = (iphdr*)((char*)packet + sizeof(ethhdr));

    // print ip_header
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n", (unsigned int)ip_header->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",
           (unsigned int)ip_header->ihl, ((unsigned int)(ip_header->ihl)) * 4);
    printf("   |-Type Of Service   : %d\n", (unsigned int)ip_header->tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
           ntohs(ip_header->tot_len));
    printf("   |-Identification    : %d\n", ntohs(ip_header->id));
    printf("   |-TTL      : %d\n", (unsigned int)ip_header->ttl);
    printf("   |-Protocol : %d\n", (unsigned int)ip_header->protocol);
    printf("   |-Checksum : %d\n", ntohs(ip_header->check));
    printf("   |-Source IP        : %s\n",
           inet_ntoa(*(in_addr*)&ip_header->saddr));
    printf("   |-Destination IP   : %s\n",
           inet_ntoa(*(in_addr*)&ip_header->daddr));
    if (ip_header->protocol == 17) {
    }

    printf("\n\n");
}

int main() {
    pcap_t* descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open capture file for offline processing
    char file[] = "data/dns-mail-2.pcap";
    descr = pcap_open_offline(file, errbuf);
    if (descr == NULL) {
        printf("pcap_open_offline() failed: %s\n", errbuf);
        return 1;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 10, packetHandler, NULL) < 0) {
        printf("pcap_loop() failed\n");
        return 1;
    }
    printf("capture finished\n");
    pcap_close(descr);
    return 0;
}
