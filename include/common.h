#ifndef _COMMON_H_
#define _COMMON_H_

#include <string>

enum CAPTURE_SOURCE {
	CAPTURE_SOURCE_NONE,
	CAPTURE_SOURCE_FILE,
	CAPTURE_SOURCE_DEVICE
};

enum CAPTURE_RUN_RESULT {
	CAPTURE_RUN_RESULT_OK,
	CAPTURE_RUN_RESULT_ERROR
};

struct Config {
	std::string source_name;	// net device name, or capture file path
};

#endif // _COMMON_H_