#ifndef _COMMON_H_
#define _COMMON_H_

#include <string>

enum CAPTURE_SOURCE {
    CAPTURE_SOURCE_NONE,
    CAPTURE_SOURCE_FILE,
    CAPTURE_SOURCE_DEVICE
};

enum CAPTURE_RUN_RESULT { CAPTURE_RUN_RESULT_OK, CAPTURE_RUN_RESULT_ERROR };

struct Config {
    std::string source_name;  // net device name, or capture file path
	std::string workdir = "../";
	std::string features_dump_file = "dns_features.csv";
    bool train_mode;   // train mode

	Config(bool train_mode=true) : train_mode(train_mode) {
#ifdef _MACOS_
		source_name = "en0";
#elif _LINUX_
		source_name = "eth0";	
#endif	// _MACOS_
	}

	Config(std::string source_name, std::string workdir, bool train_mode=false) : source_name(source_name), workdir(workdir), train_mode(train_mode) {}
};

#endif  // _COMMON_H_