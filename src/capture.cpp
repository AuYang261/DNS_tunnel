#include "capture.h"

#include <iostream>
#include <csignal>
#include <unistd.h>

#include "common.h"

volatile sig_atomic_t g_quit = 0;

static void sigintHandler(int sig) {
    if (sig == SIGINT) {
        printf("Interrupt signal received, stopping...\n");
        g_quit = 1;
    }
}

CaptureFile::CaptureFile(Config config) : Capture(config) {
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
    // getPcapLiveDeviceByName() returns nullptr if failed
    dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(
        config.source_name);
    // print device information
    if (dev == nullptr) {
        throw std::runtime_error("Failed to get capture device");
    }
    // open device
    if (!dev->open()) {
        throw std::runtime_error("Failed to open capture device");
    }
    // set dns filter
    if (!dev->setFilter("udp port 53")) {
        printf("Warning: failed to set filter\n");
    }
    
    printDeviceInfo();
}

CAPTURE_RUN_RESULT CaptureDevice::run() {
    // set interrupt action
    signal(SIGINT, sigintHandler);
    // start capturing
    printf("Starting capture...\n");
    if (!dev->startCapture(onPacketArrives, nullptr)) {
        throw std::runtime_error("Failed to start capturing");
    }
    // wait for keyboard interrupt
    while (!g_quit) {
        sleep(3);
        // TODO: display some statistics
    }
    // stop capturing
    dev->stopCapture();
    PacketAnalyzer::getInstance().finish();
    return CAPTURE_RUN_RESULT_OK;
}

void CaptureDevice::printDeviceInfo() {
    printf("Interface info:\n");
    printf("   Interface name:        %s\n", dev->getName().c_str());
    printf("   Interface description: %s\n", dev->getDesc().c_str());
    printf("   MAC address:           %s\n", dev->getMacAddress().toString().c_str());
    printf("   Default gateway:       %s\n", dev->getDefaultGateway().toString().c_str());
    printf("   Interface MTU:         %d\n", dev->getMtu());
    printf("   Major DNS server:      %s\n", dev->getDnsServers().front().toString().c_str());
    printf("   Interface IPv4 addr:   %s\n", dev->getIPv4Address().toString().c_str());
}

void CaptureDevice::onPacketArrives(pcpp::RawPacket* raw_packet,
                                    pcpp::PcapLiveDevice* dev, void* cookie) {
    timespec &&time_stamp = raw_packet->getPacketTimeStamp();
    printf("Packet received at %ld.%09ld, raw packet len: %d\n", time_stamp.tv_sec, time_stamp.tv_nsec, raw_packet->getRawDataLen());
    PacketAnalyzer::getInstance().analysePacket(raw_packet);
}