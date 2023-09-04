#ifndef _ANALYSE_H_
#define _ANALYSE_H_

#include <Python.h>

#include <fstream>
#include <map>
#include <queue>
#include <tuple>

#include "common.h"
#include "packets.h"

struct DNSFeatures {
    int subdomain_len = 0;
    // 子域名大写字母数
    int capital_count = 0;
    // 子域名信息熵
    double entropy = 0;
    // 子域名的最长元音距
    int longest_vowel_distance = 0;
    // 响应时间，秒
    double response_time;
    // 有效载荷的上传/下载比
    double payload_up_down_ratio = 0;
    // 窗口内请求数
    int request_num_in_long_window = 0;
    // 长短窗口请求比
    double long_short_term_ratio;
    PyObject* toPyTuple() const;
};

// id -> (DNSFeatures, timestamp)
typedef std::map<uint32_t, DNSFeatures> DNSFeaturesMap;
// slide window
typedef std::queue<DNSPacket> DNSPacketWindow;
// number of each subdomain in slide window
typedef std::map<std::string, int> SecondaryDomainCountMap;

double operator-(const timespec& lhs, const double rhs);

class PacketAnalyzer {
   public:
    void init(const Config& config);
    void finish();
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
    void loadModel();
    void saveModel();
    double predict(const DNSFeatures&);
    void dump(const DNSFeatures&);
    void analyseQuery(DNSPacket& dns_packet);
    void analyseResponse(DNSPacket& dns_packet);
    static std::string getSecondaryDomain(const std::string& domain);
    static std::string getSubdomain(const std::string& domain);
    static double toSecond(const timespec& ts);

    bool if_dump;
    bool display_dns;
    PyObject* py_script;
    PyObject* func_load_model;
    PyObject* func_save_model;
    PyObject* func_predict;
    PyObject* model;
    DNSFeaturesMap dns_features_map;
    DNSPacketWindow packet_window_long;
    DNSPacketWindow packet_window_short;
    SecondaryDomainCountMap domain_count_long;
    SecondaryDomainCountMap domain_count_short;
    std::fstream dump_file;
    std::string workdir;
    std::string features_file_name;

    static inline const std::string model_path = "./models/";
    static inline const std::string model_name = "model";
    static inline const std::string py_script_path = "./py/";
    static inline const std::string py_script_name = "iforest";
    // static inline const std::string features_file_name = "dns_features.csv";
    static inline const int LONG_TERM_WIDTH = 20;  // in second
    static inline const int SHORT_TERM_WIDTH = 2;  // in second

    inline static PacketAnalyzer* instance;
};

#endif