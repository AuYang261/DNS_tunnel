#include "packets.h"

DNSPacket parseDNSPacket(pcpp::RawPacket* packet) {
    DNSPacket dns_packet{};
    pcpp::Packet parsed_packet(packet);
    pcpp::DnsLayer* dns_layer = parsed_packet.getLayerOfType<pcpp::DnsLayer>();
    pcpp::IPLayer* ip_layer = parsed_packet.getLayerOfType<pcpp::IPLayer>();
    dns_packet.id = dns_layer->getDnsHeader()->transactionID;

    
    dns_packet.timestamp = packet->getPacketTimeStamp();
    if (dns_layer == nullptr) {
        dns_packet.type = DNS_TYPE::DNS_TYPE_NONE;
        return dns_packet;
    }
    dns_packet.size = dns_layer->getDataLen() - 12;     // header size = 12
    if (dns_layer->getAnswerCount() > 0) {  // response
        dns_packet.type = DNS_TYPE::DNS_TYPE_RESPONSE;
        auto&& src_ip = ip_layer->getSrcIPAddress();
        if (src_ip.isIPv6()) {  // ipv6
            uint8_t ip_bytes_buffer[16];   // to handle ipv6 addr
            src_ip.getIPv6().copyTo(ip_bytes_buffer);
            dns_packet.id ^= *(uint32_t *)ip_bytes_buffer;
        } else {    // ipv4
            dns_packet.id ^= (uint32_t)src_ip.getIPv4().toInt();
        }
    } else {        // query
        dns_packet.type = DNS_TYPE::DNS_TYPE_QUERY;
        // add request domain to the dns_packet
        pcpp::DnsQuery* dns_query = dns_layer->getFirstQuery();
        if (dns_query != nullptr) {
            dns_packet.domain = dns_query->getName();
        }
        auto&& dst_ip = ip_layer->getDstIPAddress();
        if (dst_ip.isIPv6()) {  // ipv6
            uint8_t ip_bytes_buffer[16];   // to handle ipv6 addr
            dst_ip.getIPv6().copyTo(ip_bytes_buffer);
            dns_packet.id ^= *(uint32_t *)ip_bytes_buffer;
        } else {    // ipv4
            dns_packet.id ^= (uint32_t)dst_ip.getIPv4().toInt();
        }
    }

    return dns_packet;
}