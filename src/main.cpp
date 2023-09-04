#include "capture.h"
#include "common.h"
#include "packets.h"
#include <unistd.h>
#include <getopt.h>
#include <iostream>


int main(int argc, char* argv[]) {
    Config config;
    bool use_live_device = true;
    // read config from command line options
    static struct option long_options[] = {
        {"pcap-dump", no_argument, 0, 'd'},
        {"input-file", required_argument, 0, 'f'},
        {"work-dir", required_argument, 0, 'w'},
        {"train-mode", no_argument, 0, 't'},
        {"display-dns", no_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "df:w:tsh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'd':
                use_live_device = false;
                break;
            case 'f':
                config.source_name = optarg;
                break;
            case 'w':
                config.workdir = optarg;
                break;
            case 't':
                config.train_mode = true;
                break;
            case 's':
                config.display_dns = true;
                break;
            case 'h':
                std::cout << "Usage: " << argv[0] << " [--pcap-dump / -d] [--input-file / -f source_name] [--work-dir / -w workdir] [--display-dns / -s] [--train-mode / -t]" << std::endl;
                std::cout << "      --pcap-dump: use pcap dump file" << std::endl;
                std::cout << "      --input-file: specify the input file name" << std::endl;
                std::cout << "      --work-dir: specify the work directory" << std::endl;
                std::cout << "      --display-dns: display dns packets" << std::endl;
                std::cout << "      --train-mode: enable training mode" << std::endl;
                exit(EXIT_SUCCESS);
            default:
                std::cout << "Usage: " << argv[0] << " [--pcap-dump / -d] [--input-file / -f source_name] [--work-dir / -w workdir] [--display-dns / -s] [--train-mode / -t]" << std::endl;
                exit(EXIT_FAILURE);
        }
    }
    std::cout << "Config info:" << std::endl;
    std::cout << "    use_live_device: " << (use_live_device ? 'y': 'n') << std::endl;
    std::cout << "    source_name: " << config.source_name << std::endl;
    std::cout << "    workdir: " << config.workdir << std::endl;
    std::cout << "    display_dns: " << (config.display_dns ? 'y': 'n') << std::endl;
    std::cout << "    train_mode: " << (config.train_mode ? 'y': 'n') << std::endl;

    // run capture and analysis
    if (use_live_device) {
        CaptureDevice capture(config);
        capture.run();
    } else {
        CaptureFile capture(config);
        capture.run();
    }   

    // config.source_name = "data/20230831_1.pcapng";
    // CaptureFile capture(config);
    // config.workdir = "../";
    // config.features_dump_file = "dns_features_normal.csv";
    // CaptureDevice capture(config);
    
    return 0;
}