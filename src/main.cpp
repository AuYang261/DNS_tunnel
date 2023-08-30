#include "capture.h"
#include "common.h"
#include "packets.h"

int main() {
    // first test capture file
    Config config;
    // // // config.source_name = "../data/dns-mail-2.pcap";
    // // CaptureFile capture(config);
    // capture.run();
    CaptureDevice capture(config);
    capture.run();
    return 0;
}