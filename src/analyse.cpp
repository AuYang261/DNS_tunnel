#include "analyse.h"

#include <iostream>  // for test

time_t operator-(timespec& lhs, timespec& rhs) {
    // seconds
    return (lhs.tv_sec - rhs.tv_sec) - (lhs.tv_nsec < rhs.tv_nsec);
}

#define check_null(val)                                           \
    if (val == nullptr) {                                         \
        PyErr_Print();                                            \
        throw std::runtime_error(#val + std::string(" is null")); \
    }

PacketAnalyzer::PacketAnalyzer() {
    // TODO
}

void PacketAnalyzer::init() {
    Py_Initialize();
    PyRun_SimpleString("import sys");
    // add path
    PyRun_SimpleString(("sys.path.append(\"" + py_script_path + "\")").c_str());
    PyErr_Print();
    // print current path
    // PyRun_SimpleString("import os");
    // PyRun_SimpleString("print(os.getcwd())");
    // import module
    py_script = PyImport_ImportModule(py_script_name.c_str());
    check_null(py_script);

    // get function load_model
    func_load_model = PyObject_GetAttrString(py_script, "load_model");
    check_null(func_load_model);
    if (!PyCallable_Check(func_load_model)) {
        throw std::runtime_error("load_model is not callable");
    }
    // get function predict
    func_predict = PyObject_GetAttrString(py_script, "predict");
    check_null(func_predict);
    if (!PyCallable_Check(func_predict)) {
        throw std::runtime_error("predict is not callable");
    }

    // pass a string to function load_model
    PyObject* load_model_args =
        Py_BuildValue("(s)", (model_path + model_name).c_str());
    check_null(load_model_args);
    // call function load_model
    model = PyObject_CallObject(func_load_model, load_model_args);
    check_null(model);
}

bool PacketAnalyzer::predict(const DNSFeatures& dns_features) {
    // TODO
    // get function predict's parameter
    PyObject* predict_args = Py_BuildValue("(O,[i,i])", model, 2, 2);
    // call function predict
    PyObject* predict_result = PyObject_CallObject(func_predict, predict_args);
    check_null(predict_result);
    // check if predict_result is true
    return PyObject_IsTrue(predict_result);
}

void PacketAnalyzer::analysePacket(pcpp::RawPacket* packet) {
    auto&& dns_packet = parseDNSPacket(packet);
    switch (dns_packet.type) {
        case DNS_TYPE::DNS_TYPE_QUERY:
            analyseQuery(dns_packet);
            break;
        case DNS_TYPE::DNS_TYPE_RESPONSE:
            analyseResponse(dns_packet);
            break;
        default:
            break;
    }
}

void PacketAnalyzer::analyseQuery(DNSPacket& dns_packet) {
    dns_packet_window.push(dns_packet);
    while (!dns_packet_window.empty() &&
           dns_packet_window.front().timestamp - dns_packet.timestamp >
               window_time_seconds) {
        // pop and update secondary_domain_count_map
        auto subdomain_count_i = secondary_domain_count_map.find(
            getSecondaryDomain(dns_packet_window.front().domain));
        if (subdomain_count_i != secondary_domain_count_map.end()) {
            subdomain_count_i->second--;
        }
        if (subdomain_count_i->second == 0) {
            secondary_domain_count_map.erase(subdomain_count_i);
        }
        dns_packet_window.pop();
    }
    // update secondary_domain_count_map
    auto secondary_domain_count_i =
        secondary_domain_count_map.find(getSecondaryDomain(dns_packet.domain));
    if (secondary_domain_count_i == secondary_domain_count_map.end()) {
        secondary_domain_count_map[dns_packet.domain] = 1;
    } else {
        secondary_domain_count_i->second++;
    }

    // TODO
    // analyse query to DNSFeatures
    DNSFeatures dns_features{};
    std::string subdomain = getSubdomain(dns_packet.domain);
    dns_features.subdomain_len = subdomain.length();
    for (auto&& c : subdomain) {
        if (c >= 'A' && c <= 'Z') {
            dns_features.capital_count++;
        }
    }
    // entropy
    std::map<char, int> char_count_map;
    for (auto&& c : subdomain) {
        char_count_map[c]++;
    }
    for (auto&& [_, count] : char_count_map) {
        double p = (double)count / subdomain.length();
        dns_features.entropy -= p * log2(p);
    }
    // longest_vowel_distance
    int vowel_distance = 0;
    for (auto&& c : subdomain) {
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            vowel_distance = 0;
        } else {
            vowel_distance++;
        }
        dns_features.longest_vowel_distance =
            std::max(dns_features.longest_vowel_distance, vowel_distance);
    }
    // request_num_in_window
    dns_features.request_num_in_window = secondary_domain_count_i->second;
    // response_time, record as the request time temporarily
    dns_features.response_time = dns_packet.timestamp;
    // payload_up_down_ratio, record as query size temporarily
    dns_features.payload_up_down_ratio = dns_packet.size;

    if (dns_features_map.count(dns_packet.transactionID) == 0) {
        dns_features_map[dns_packet.transactionID] = dns_features;
    }
}

void PacketAnalyzer::analyseResponse(DNSPacket& dns_packet) {
    // TODO
    // analyse response to DNSFeatures
    DNSFeatures dns_features{};
    auto dns_feature_i = dns_features_map.find(dns_packet.transactionID);
    if (dns_feature_i == dns_features_map.end()) {
    } else {
    }
}

std::string PacketAnalyzer::getSecondaryDomain(const std::string& domain) {
    auto&& pos = domain.rfind('.', domain.rfind('.') - 1);
    if (pos == std::string::npos) {
        return domain;
    }
    return domain.substr(pos + 1);
}

std::string PacketAnalyzer::getSubdomain(const std::string& domain) {
    auto&& pos = domain.rfind('.', domain.rfind('.') - 1);
    if (pos == std::string::npos) {
        return domain;
    }
    return domain.substr(0, pos);
}
