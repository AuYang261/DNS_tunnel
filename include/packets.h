#ifndef _PACKETS_H_
#define _PACKETS_H_

#include <DnsLayer.h>
#include <Packet.h>

enum DNS_TYPE { DNS_TYPE_NONE, DNS_TYPE_QUERY, DNS_TYPE_RESPONSE };

struct DNSPacket {
    uint16_t transactionID;
    timespec timestamp;
    DNS_TYPE type;
    std::string domain;
    int size;
};

DNSPacket parseDNSPacket(pcpp::RawPacket* packet);

#endif