#include <pcap.h>
#include <time.h>

#include <iostream>

#include "DNS.h"

void packetHandler(unsigned char* arg, const struct pcap_pkthdr* pkthdr,
                   const unsigned char* packet);
void print_ip_header(iphdr* iphdr);
void print_udp_header(udphdr* udphdr);

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
    // 设置过滤器，捕获端口为53的UDP数据包
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    pcap_compile(descr, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(descr, &fp);

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 10, packetHandler, NULL) < 0) {
        printf("pcap_loop() failed\n");
        return 1;
    }
    printf("capture finished\n");
    pcap_close(descr);
    return 0;
}

void packetHandler(unsigned char* arg, const struct pcap_pkthdr* pkthdr,
                   const unsigned char* packet) {
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t*)&pkthdr->ts.tv_sec));
    void* end = (void*)(packet + pkthdr->caplen);

    // IP
    ethhdr* eth_header = (ethhdr*)packet;
    if (eth_header->h_proto != htons(ETH_P_IP)) {
        printf("not ip packet\n");
        return;
    }
    iphdr* ip_header = (iphdr*)((char*)packet + sizeof(ethhdr));
    if (ip_header >= end) {
        printf("ip_header out of range\n");
        return;
    }
    print_ip_header(ip_header);

    // UDP
    if (ip_header->protocol != IPPROTO_UDP) {
        printf("not udp packet\n");
        return;
    }
    udphdr* udp_header = (udphdr*)((char*)ip_header + ip_header->ihl * 4);
    if (udp_header >= end) {
        printf("udp_header out of range\n");
        return;
    }
    print_udp_header(udp_header);

    // DNS
    if (ntohs(udp_header->dest) != 53 && ntohs(udp_header->source) != 53) {
        printf("not dns packet\n");
        return;
    }
    void* dns_pkt = (char*)udp_header + sizeof(udphdr);
    if (dns_pkt >= end) {
        printf("dns_request out of range\n");
        return;
    }
    DNS_Packet dns_packet(dns_pkt, pkthdr->caplen - sizeof(ethhdr) -
                                       sizeof(iphdr) - sizeof(udphdr));
    dns_packet.parseDomainName(dns_pkt, end);
    dns_packet.display();
    printf("-------------------\n\n");
}

void print_ip_header(iphdr* ip_header) {
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
    printf("\n\n");
}

void print_udp_header(udphdr* udp_header) {
    // print udp_header
    printf("UDP Header\n");
    printf("   |-Source Port      : %d\n", ntohs(udp_header->source));
    printf("   |-Destination Port : %d\n", ntohs(udp_header->dest));
    printf("   |-UDP Length       : %d\n", ntohs(udp_header->len));
    printf("   |-UDP Checksum     : %d\n", ntohs(udp_header->check));
    printf("\n\n");
}
