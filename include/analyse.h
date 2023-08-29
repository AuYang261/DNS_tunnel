#ifndef _ANALYSE_H_
#define _ANALYSE_H_

#include <Python.h>

#include "packets.h"

struct DNSFeatures {
    int subdomain_len;
    // 子域名大写字母数
    int capital_count;
    // 子域名信息熵
    int entropy;
    // 子域名的最长元音距
    int longest_vowel_distance;
    // 窗口内请求数
    int request_num_in_window;
    // 响应时间
    int response_time;
    // 有效载荷的上传/下载比
    double payload_up_down_ratio;
};

typedef std::map<uint16_t, DNSFeatures> DNSFeaturesMap;

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
    bool predict(const DNSFeatures&);

   private:
    PacketAnalyzer();
    inline static PacketAnalyzer* instance;
    // TODO: statistics maintained by the analyzer
    timespec start_timestamp{};
    PyObject* py_script;
    PyObject* func_load_model;
    PyObject* func_predict;
    PyObject* model;
    DNSFeaturesMap dns_features_map;

    static inline const std::string model_path = "../models/";
    static inline const std::string model_name = "model";
    static inline const std::string py_script_path = "../py/";
    static inline const std::string py_script_name = "iforest";

    void analyseQuery(DNSPacket& dns_packet);
    void analyseResponse(DNSPacket& dns_packet);
};

#endif