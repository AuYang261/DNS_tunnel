#ifndef HEADERS_H
#define HEADERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <string.h>

#include <memory>
#include <string>
#include <vector>

struct DomainName {
    DomainName() = default;
    DomainName(void*&, const void*);
    ~DomainName() = default;
    std::string toString() const;
    void parseLabels(void*&, const void*);
    void parseOffset(void*, const void*);

    std::vector<std::string> labels;
    ptrdiff_t offset;
    bool isOffset;
};

struct DNS_Base {
   public:
    DNS_Base(uint16_t transactionID, uint16_t flags, uint16_t questions,
             uint16_t answerRRs, uint16_t authorityRRs, uint16_t additionalRRs);
    ~DNS_Base() = default;
    void ntohs();

    uint16_t transactionID;
    uint16_t flags;
    uint16_t questions;
    std::array<uint16_t, 3> RRs;
    // uint16_t answerRRs;
    // uint16_t authorityRRs;
    // uint16_t additionalRRs;
};

enum QueryType : uint16_t {
    A = 0x0001,
    NS = 0x0002,
    CNAME = 0x0005,
    SOA = 0x0006,
    PTR = 0x000c,
    MX = 0x000f,
    TXT = 0x0010,
    AAAA = 0x001c
};

struct DNS_Query {
   public:
    DNS_Query(void*&, const void*);
    DNS_Query(DomainName domainName, QueryType queryType, uint16_t queryClass);
    ~DNS_Query() = default;
    void ntoh();

    DomainName domainName;
    QueryType queryType;
    uint16_t queryClass;  // 1
};

class DNS_Queries {
   public:
    typedef std::vector<std::unique_ptr<DNS_Query>> Queries;

    DNS_Queries() = default;
    ~DNS_Queries() = default;

    void addQuery(std::unique_ptr<DNS_Query>&&);
    const Queries& getQuereis() const;
    void display() const;
    void parseDomainName(void*, const void*);

   private:
    Queries queries;
};

struct DNS_Resource_Record {
   public:
    DNS_Resource_Record(void*&, const void*);
    DNS_Resource_Record(DomainName domainName, QueryType queryType,
                        uint16_t queryClass, uint32_t timeToLive,
                        uint16_t dataLen, const char* data);
    ~DNS_Resource_Record() = default;
    void ntoh();
    std::string dataToString() const;
    inline bool dataIsDomainName() const;

    DomainName domainName;
    QueryType queryType;
    uint16_t queryClass;  // 1
    uint32_t timeToLive;
    uint16_t dataLen;
    const char* data;
    DomainName dataDomainName;
};

class DNS_RRs {
   public:
    typedef std::vector<std::unique_ptr<DNS_Resource_Record>> RRs_T;
    enum Type { ANSWER, AUTHORITY, ADDITIONAL } type;
    static constexpr std::array<const char*, 3> type_s = {"ANSWER", "AUTHORITY",
                                                          "ADDITIONAL"};

    DNS_RRs(Type);
    DNS_RRs(const DNS_RRs&) = delete;
    DNS_RRs(DNS_RRs&&) = default;
    ~DNS_RRs() = default;

    void addRR(std::unique_ptr<DNS_Resource_Record>&&);
    const RRs_T& getRRs() const;
    void display() const;
    void parseDomainName(void*, const void*);

   private:
    RRs_T RRs;
};

struct DNS_Packet {
   public:
    DNS_Packet(void* packet, size_t packet_len);
    ~DNS_Packet() = default;
    void display() const;
    void parseDomainName(void*, const void*);

    DNS_Base* base;
    DNS_Queries queries;
    std::array<DNS_RRs, 3> RRs_3;
};

#endif  // DNS_H