#include "analyse.h"
#include <iostream>		// for test

PacketAnalyzer::PacketAnalyzer() {
	// TODO
}

void PacketAnalyzer::analysePacket(pcpp::RawPacket* packet) {
	auto&& dns_features = parseDNSPacket(packet);
	// test print dns_features
	std::cout << "dns_features.type: " << dns_features.type << std::endl;
	std::cout << "dns_features.num_answers: " << dns_features.num_answers << std::endl;
	// print timestamp in a readable format
	printf("timestamp: %ld.%09ld\n", dns_features.timestamp.tv_sec, dns_features.timestamp.tv_nsec);

}