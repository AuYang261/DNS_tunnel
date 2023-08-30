#ifndef _PACKETS_H_
#define _PACKETS_H_

#include <DnsLayer.h>
#include <IPLayer.h>
#include <Packet.h>

enum DNS_TYPE { DNS_TYPE_NONE, DNS_TYPE_QUERY, DNS_TYPE_RESPONSE };

struct DNSPacket {
    uint32_t id;     // TODO: update to hash ID, hash with source and dest IP
    timespec timestamp;
    DNS_TYPE type;
    std::string domain;
    int size;
};

DNSPacket parseDNSPacket(pcpp::RawPacket* packet);

#endif