#ifndef _PACKETS_H_
#define _PACKETS_H_

#include <DnsLayer.h>
#include <IPLayer.h>
#include <Packet.h>

enum DNS_TYPE { DNS_TYPE_NONE, DNS_TYPE_QUERY, DNS_TYPE_RESPONSE };

struct DNSPacket {
    uint32_t id;    // hashed id
    timespec timestamp;
    DNS_TYPE type;  // query or response
    std::string domain; // query domain name, used only in query packet
    int size;   // DNS payload size
};

DNSPacket parseDNSPacket(pcpp::RawPacket* packet);

#endif