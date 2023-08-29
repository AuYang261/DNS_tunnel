#include "analyse.h"

#include <iostream>  // for test

#define check_null(val)                                           \
    if (val == nullptr) {                                         \
        PyErr_Print();                                            \
        throw std::runtime_error(#val + std::string(" is null")); \
    }

PacketAnalyzer::PacketAnalyzer() {
    // TODO
}

void PacketAnalyzer::init() {
    start_timestamp.tv_sec = 0;
    start_timestamp.tv_nsec = 0;
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
    // TODO
    // analyse query to DNSFeatures
    DNSFeatures dns_features{};
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
