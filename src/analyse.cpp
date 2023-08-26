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
	if (start_timestamp.tv_sec == 0 && start_timestamp.tv_nsec == 0) [[unlikely]] {
		start_timestamp = dns_features.timestamp;
		dns_features.timestamp.tv_sec = 0;
		dns_features.timestamp.tv_nsec = 0;
	} else {
		dns_features.timestamp.tv_sec -= start_timestamp.tv_sec;
		dns_features.timestamp.tv_nsec -= start_timestamp.tv_nsec;
	}
	printf("timestamp: %ld.%09ld\n", dns_features.timestamp.tv_sec, dns_features.timestamp.tv_nsec);

}