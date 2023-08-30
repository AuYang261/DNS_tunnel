#ifndef _CAPTURE_H_
#define _CAPTURE_H_
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>

#include "analyse.h"
#include "common.h"

class Capture
{
public:
   Capture(Config config){
      PacketAnalyzer::getInstance().init(config);
   };
   virtual ~Capture(){};
   virtual CAPTURE_RUN_RESULT run() = 0;

protected:
};

class CaptureFile : public Capture
{
public:
   CaptureFile(Config config);
   virtual ~CaptureFile() { reader->close(); }
   CAPTURE_RUN_RESULT run() override;

private:
   pcpp::IFileReaderDevice *reader;
};

class CaptureDevice : public Capture
{
public:
   CaptureDevice(Config config);
   virtual ~CaptureDevice() { dev->close(); }
   CAPTURE_RUN_RESULT run() override;

private:
   pcpp::PcapLiveDevice *dev;
   // struct PacketStats
   // {
   //    unsigned int dnsPacketCount;
   //    void clear() { dnsPacketCount = 0; }
   //    PacketStats() { clear(); }
   //    void consumePacket(pcpp::Packet *packet) {
   //       if (packet->isPacketOfType(pcpp::DNS))
   //          dnsPacketCount++;
   //    }
   //    void printToConsole() {
   //       printf("DNS packets count: %d\n", dnsPacketCount);
   //    }
   // } packet_stats;
   void printDeviceInfo();
   static void onPacketArrives(pcpp::RawPacket *packet,
                               pcpp::PcapLiveDevice *dev, void *cookie);
};

#endif // _CAPTURE_H_