#include "capture.h"
#include "common.h"
#include "packets.h"

int main() {
    // first test capture file
    Config config;
    // // config.source_name = "../data/20230831_1.pcapng";
    // CaptureFile capture(config);
    CaptureDevice capture(config);
    capture.run();
    return 0;
}