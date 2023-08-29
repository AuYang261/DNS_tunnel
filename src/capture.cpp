#include "capture.h"

#include <iostream>

#include "common.h"

CaptureFile::CaptureFile(Config config) : Capture(config) {
    PacketAnalyzer::getInstance().init(config);
    reader = pcpp::IFileReaderDevice::getReader(config.source_name);
    if (reader == nullptr || !reader->open()) {
        throw std::runtime_error("Failed to open capture file");
    }
    if (!reader->setFilter("udp port 53")) {  // set filter for dns
        printf("Warning: failed to set filter\n");
    }
}

CAPTURE_RUN_RESULT CaptureFile::run() {
    pcpp::RawPacket rawPacket;
    try {
        while (reader->getNextPacket(rawPacket)) {
            PacketAnalyzer::getInstance().analysePacket(&rawPacket);
        }
    } catch (const std::exception& e)  // get next packet error
    {
        std::cerr << e.what() << '\n';
        return CAPTURE_RUN_RESULT_ERROR;
    }

    return CAPTURE_RUN_RESULT_OK;
}

CaptureDevice::CaptureDevice(Config config) : Capture(config) {
    // TODO
}

CAPTURE_RUN_RESULT CaptureDevice::run() {
    // TODO
    return CAPTURE_RUN_RESULT_OK;
}

void CaptureDevice::onPacketArrives(pcpp::RawPacket* packet,
                                    pcpp::PcapLiveDevice* dev, void* cookie) {
    // TODO
}