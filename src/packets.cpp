#include "packets.h"

DNSPacket parseDNSPacket(pcpp::RawPacket* packet) {
    DNSPacket dns_packet{};
    pcpp::Packet parsed_packet(packet);
    pcpp::DnsLayer* dns_layer = parsed_packet.getLayerOfType<pcpp::DnsLayer>();
    dns_packet.transactionID = dns_layer->getDnsHeader()->transactionID;
    dns_packet.timestamp = packet->getPacketTimeStamp();
    if (dns_layer == nullptr) {
        dns_packet.type = DNS_TYPE::DNS_TYPE_NONE;
        return dns_packet;
    }
    // TODO: add size to dns_packet, which means the size of the up/down data
    // in, used to calculate payload_up_down_ratio
    if (dns_layer->getAnswerCount() > 0) {
        dns_packet.type = DNS_TYPE::DNS_TYPE_RESPONSE;
        pcpp::DnsResource* dns_resource = dns_layer->getFirstAnswer();
        while (dns_resource != nullptr) {
            if (dns_resource->getDnsType() == pcpp::DNS_TYPE_A ||
                dns_resource->getDnsType() == pcpp::DNS_TYPE_AAAA) {
                dns_packet.num_answers++;
            } else if (dns_resource->getDnsType() == pcpp::DNS_TYPE_NS) {
                dns_packet.num_authority++;
            }
            dns_resource = dns_layer->getNextAnswer(dns_resource);
        }
    } else {
        dns_packet.type = DNS_TYPE::DNS_TYPE_QUERY;
        // add request domain to the dns_packet
        pcpp::DnsQuery* dns_query = dns_layer->getFirstQuery();
        if (dns_query != nullptr) {
            dns_packet.domain = dns_query->getName();
        }
    }

    return dns_packet;
}