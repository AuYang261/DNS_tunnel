#include "analyse.h"

#include <iostream>  // for test

#define check_null(val)                                           \
    if (val == nullptr) {                                         \
        PyErr_Print();                                            \
        throw std::runtime_error(#val + std::string(" is null")); \
    }

double operator-(const timespec& lhs, const double rhs) {
    return lhs.tv_sec + lhs.tv_nsec / 1000000000.0 - rhs;
}

int operator-(const timespec& lhs, const timespec& rhs) {
    return lhs.tv_sec - rhs.tv_sec - (lhs.tv_nsec < rhs.tv_nsec);
}

std::fstream& operator<<(std::fstream& fs, const DNSFeatures& dns_features) {
    fs << dns_features.subdomain_len << "," << dns_features.capital_count << ","
       << dns_features.entropy << "," << dns_features.longest_vowel_distance
       << "," << dns_features.request_num_in_long_window << ","
       << dns_features.response_time << ","
       << dns_features.payload_up_down_ratio << ","
       << dns_features.long_short_term_ratio << std::endl;
    return fs;
}

PyObject* DNSFeatures::toPyTuple() const {
    return Py_BuildValue("(i,i,d,i,i,d,d,d)", subdomain_len, capital_count,
                         entropy, longest_vowel_distance,
                         request_num_in_long_window, response_time,
                         payload_up_down_ratio, long_short_term_ratio);
}

PacketAnalyzer::PacketAnalyzer() {}

void PacketAnalyzer::init(const Config& config) {
    if_dump = config.train_mode;
    workdir = config.workdir;
    features_file_name = config.features_dump_file;
    display_dns = config.display_dns;
    threshold = config.threshold;

    // get config from the model
    if (!threshold) {
        std::fstream model_file(workdir + model_path + preconfig_name,
                                std::ios::in);
        if (model_file.is_open()) {
            std::string line;
            std::getline(model_file, line);
            threshold = std::stod(line);
            model_file.close();
        }
    }
    // open dump file
    if (if_dump) {
        dump_file = std::fstream(workdir + model_path + features_file_name,
                                 std::ios::out | std::ios::app);
    }
    Py_Initialize();
    PyRun_SimpleString("import sys");
    // add path
    PyRun_SimpleString(
        ("sys.path.append(\"" + workdir + py_script_path + "\")").c_str());
    PyErr_Print();
    // import py_script
    py_script = PyImport_ImportModule(py_script_name.c_str());
    check_null(py_script);

    // get function load_model
    func_load_model = PyObject_GetAttrString(py_script, "load_model");
    check_null(func_load_model);
    if (!PyCallable_Check(func_load_model)) {
        throw std::runtime_error("load_model is not callable");
    }
    // get function save_model
    func_save_model = PyObject_GetAttrString(py_script, "save_model");
    check_null(func_save_model);
    if (!PyCallable_Check(func_save_model)) {
        throw std::runtime_error("save_model is not callable");
    }
    // get function predict
    func_predict = PyObject_GetAttrString(py_script, "predict");
    check_null(func_predict);
    if (!PyCallable_Check(func_predict)) {
        throw std::runtime_error("predict is not callable");
    }

    if (!if_dump) {
        loadModel();
    }
}

void PacketAnalyzer::finish() {
    printf("Clean up analyzer...\n");
    // TODO: display stats
    if (if_dump) {
        dump_file.close();
    } else {
        // can do some finishing cleaning
    }
    Py_Finalize();
}

void PacketAnalyzer::loadModel() {
    // pass a string to function load_model
    PyObject* load_model_args =
        Py_BuildValue("(s)", (workdir + model_path + model_name).c_str());
    check_null(load_model_args);
    // call function load_model
    model = PyObject_CallObject(func_load_model, load_model_args);
    check_null(model);
}

// void PacketAnalyzer::saveModel() {
//     // pass model and a string to function save_model
//     PyObject* save_model_args = Py_BuildValue(
//         "(Oss)", model, (workdir + model_path).c_str(), model_name.c_str());
//     // call function save_model
//     PyObject_CallObject(func_save_model, save_model_args);
//     PyErr_Print();
// }

double PacketAnalyzer::predict(const DNSFeatures& dns_features) {
    // get function predict's parameter
    PyObject* features = dns_features.toPyTuple();
    check_null(features);
    // pass features to function predict
    PyObject* predict_args = Py_BuildValue("(OO)", model, features);
    check_null(predict_args);

    // call function predict
    PyObject* predict_result = PyObject_CallObject(func_predict, predict_args);
    check_null(predict_result);
    // predict, needn't to save model
    // saveModel();
    // return predict_result as double
    return PyFloat_AsDouble(predict_result);
}

void PacketAnalyzer::dump(const DNSFeatures& dns_features) {
    // save dns_features to file
    dump_file << dns_features;
}

void PacketAnalyzer::analysePacket(pcpp::RawPacket* packet) {
    auto&& dns_packet = parseDNSPacket(packet, display_dns);
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
    std::cout << "analyseQuery 0x" << std::hex << dns_packet.id << std::endl;
    packet_window_long.push(dns_packet);
    while (!packet_window_long.empty() &&
           dns_packet.timestamp - packet_window_long.front().timestamp >=
               LONG_TERM_WIDTH) {
        // pop and update secondary_domain_count_map
        auto subdomain_count_i = domain_count_long.find(
            getSecondaryDomain(packet_window_long.front().domain));
        if (subdomain_count_i != domain_count_long.end()) {
            subdomain_count_i->second--;
            if (subdomain_count_i->second == 0) {
                domain_count_long.erase(subdomain_count_i);
            }
        }
        packet_window_long.pop();
    }
    packet_window_short.push(dns_packet);
    while (!packet_window_short.empty() &&
           dns_packet.timestamp - packet_window_short.front().timestamp >=
               SHORT_TERM_WIDTH) {
        // pop and update secondary_domain_count_map
        auto subdomain_count_i = domain_count_short.find(
            getSecondaryDomain(packet_window_short.front().domain));
        if (subdomain_count_i != domain_count_short.end()) {
            subdomain_count_i->second--;
            if (subdomain_count_i->second == 0) {
                domain_count_short.erase(subdomain_count_i);
            }
        }
        packet_window_short.pop();
    }
    // update secondary_domain_count_map
    auto secondary_domain = getSecondaryDomain(dns_packet.domain);
    auto domain_count_idx_long = domain_count_long.find(secondary_domain);
    if (domain_count_idx_long == domain_count_long.end()) {
        domain_count_long[secondary_domain] = 1;
    } else {
        domain_count_idx_long->second++;
    }
    auto domain_count_idx_short = domain_count_short.find(secondary_domain);
    if (domain_count_idx_short == domain_count_short.end()) {
        domain_count_short[secondary_domain] = 1;
    } else {
        domain_count_idx_short->second++;
    }

    auto current_domain_count_long = domain_count_long[secondary_domain];
    auto current_domain_count_short = domain_count_short[secondary_domain];

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
    // request_num_in_long_window
    dns_features.request_num_in_long_window = current_domain_count_long;
    // LSTR
    dns_features.long_short_term_ratio =
        (double)current_domain_count_long / current_domain_count_short;
    dns_features.response_time = toSecond(dns_packet.timestamp);
    // payload_up_down_ratio, recorded as query size temporarily
    dns_features.payload_up_down_ratio = (double)dns_packet.size;

    if (dns_features_map.count(dns_packet.id) == 0) {
        dns_features_map[dns_packet.id] = dns_features;
    } else {
        std::cout << "id: 0x" << std::hex << dns_packet.id << " already exists"
                  << std::endl;
    }
}

void PacketAnalyzer::analyseResponse(DNSPacket& dns_packet) {
    std::cout << "analyseResponse 0x" << std::hex << dns_packet.id << std::endl;
    // analyse response to DNSFeatures
    auto dns_feature_i = dns_features_map.find(dns_packet.id);
    if (dns_feature_i == dns_features_map.end()) {
        std::cout << "id: 0x" << std::hex << dns_packet.id << " not found"
                  << std::endl;
        return;
    }
    DNSFeatures& dns_features = dns_feature_i->second;
    // response_time
    dns_features.response_time =
        dns_packet.timestamp - dns_features.response_time;
    // payload_up_down_ratio
    dns_features.payload_up_down_ratio =
        dns_packet.size / dns_features.payload_up_down_ratio;

    if (if_dump) {
        // dump
        dump(dns_features);
    } else {
        // predict
        double result = predict(dns_features);
        std::cout << "id: 0x" << std::hex << dns_packet.id
                  << " confidence: " << result << std::endl;
        std::cout << "predict result: " << (result < threshold ? "abnormal"
                                                               : "normal")
                  << std::endl;
    }
    // erase dns_features
    dns_features_map.erase(dns_feature_i);
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

double PacketAnalyzer::toSecond(const timespec& ts) {
    return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}
