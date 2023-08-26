#ifndef _PACKETS_H_
#define _PACKETS_H_

#include <Packet.h>
#include <DnsLayer.h>

enum DNS_TYPE {
	DNS_TYPE_NONE,
	DNS_TYPE_QUERY,
	DNS_TYPE_RESPONSE
};

struct DNSFeatures {
	timespec timestamp;
	DNS_TYPE type;
	std::vector<std::string> domains;
	int num_answers;
	int num_authority;
};

DNSFeatures parseDNSPacket(pcpp::RawPacket* packet);

#endif