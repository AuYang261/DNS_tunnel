#ifndef _ANALYSE_H_
#define _ANALYSE_H_

#include "packets.h"

class PacketAnalyzer {
   public:
    void init();
    ~PacketAnalyzer() = delete;
    inline static PacketAnalyzer& getInstance() {
        if (instance == nullptr) {
            instance = new PacketAnalyzer();
        }
        return *instance;
    }

    void analysePacket(pcpp::RawPacket* packet);

   private:
    PacketAnalyzer();
    inline static PacketAnalyzer* instance;
    // TODO: statistics maintained by the analyzer
    timespec start_timestamp{};
};

#endif