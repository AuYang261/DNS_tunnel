#ifndef _CAPTURE_H_
#define _CAPTURE_H_
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>

#include "analyse.h"
#include "common.h"

class Capture {
   public:
    Capture(Config config){};
    ~Capture(){};
    virtual CAPTURE_RUN_RESULT run() = 0;

   protected:
};

class CaptureFile : public Capture {
   public:
    CaptureFile(Config config);
    ~CaptureFile() { delete reader; }
    CAPTURE_RUN_RESULT run() override;

   private:
    pcpp::IFileReaderDevice* reader;
};

class CaptureDevice : public Capture {
   public:
    CaptureDevice(Config config);
    ~CaptureDevice() { delete dev; }
    CAPTURE_RUN_RESULT run() override;

   private:
    pcpp::PcapLiveDevice* dev;
    static void onPacketArrives(pcpp::RawPacket* packet,
                                pcpp::PcapLiveDevice* dev, void* cookie);
};

#endif  // _CAPTURE_H_