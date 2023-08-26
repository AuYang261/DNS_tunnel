#include "packets.h"

#include "common.h"
#include "capture.h"

int main() {
	// first test capture file
	Config config;
	config.source_name = "test.pcap";
	CaptureFile capture(config);
	capture.run();
	return 0;
}