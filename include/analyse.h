#ifndef _ANALYSE_H_
#define _ANALYSE_H_

#include "packets.h"

class PacketAnalyzer {
public:
	PacketAnalyzer();
	~PacketAnalyzer() {};

	void analysePacket(pcpp::RawPacket* packet);
private:
	// TODO: statistics maintained by the analyzer
};

#endif