#include "capture.h"
#include "common.h"
#include "packets.h"

int main() {
    // first test capture file
    Config config;
    // config.source_name = "data/20230831_1.pcapng";
    // CaptureFile capture(config);
    config.workdir = "../";
    config.features_dump_file = "dns_features_normal.csv";
    CaptureDevice capture(config);
    capture.run();
    return 0;
}