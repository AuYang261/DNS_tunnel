#include "packets.h"

DNSFeatures parseDNSPacket(pcpp::RawPacket* packet) {
	DNSFeatures features{};
	pcpp::Packet parsed_packet(packet);
	pcpp::DnsLayer* dns_layer = parsed_packet.getLayerOfType<pcpp::DnsLayer>();
	features.timestamp = packet->getPacketTimeStamp();
	if (dns_layer == nullptr) {
		features.type = DNS_TYPE::DNS_TYPE_NONE;
		return features;
	}
	if (dns_layer->getAnswerCount() > 0) {
		features.type = DNS_TYPE::DNS_TYPE_RESPONSE;
		pcpp::DnsResource* dns_resource = dns_layer->getFirstAnswer();
		while (dns_resource != nullptr) {
			if (dns_resource->getDnsType() == pcpp::DNS_TYPE_A) {
				features.num_answers++;
			} else if (dns_resource->getDnsType() == pcpp::DNS_TYPE_NS) {
				features.num_authority++;
			}
			// TODO: need domain?
			dns_resource = dns_layer->getNextAnswer(dns_resource);
		}
	}
	else {
		features.type = DNS_TYPE::DNS_TYPE_QUERY;
		// TODO: add features
	}

	return features;
}