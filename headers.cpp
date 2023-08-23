#include "headers.h"

#include <stdio.h>

static inline void p_out_of_range(const void* p, const void* end) {
    if (p > end) {
        throw "p out of range";
    }
}
template <typename T>
static inline void CAST_AND_ADVANCE(T& t, void*& p, const void* end) {
    t = *(T*)p;
    p = (void*)((char*)p + sizeof(T));
    p_out_of_range(p, end);
}
template <typename T>
static inline void CAST_AND_ADVANCE(T& t, void*& p) {
    t = *(T*)p;
    p = (void*)((char*)p + sizeof(T));
}

DomainName::DomainName(void*& p, const void* end) {
    if (*(uint8_t*)p >> 6 == 0b11) {
        offset = ::ntohs(*(uint16_t*)p) & 0x3fff;
        isOffset = true;
        p = (void*)((char*)p + 2);
    } else {
        isOffset = false;
        parseLabels(p, end);
    }
}

void DomainName::parseLabels(void*& p, const void* end) {
    if (isOffset) {
        throw "isOffset";
    }
    while (true) {
        p_out_of_range(p, end);
        uint8_t len = *(uint8_t*)p;
        if (len == 0) {
            p = (void*)((char*)p + 1);
            break;
        }
        if (len >> 6 == 0b11) {
            offset = ::ntohs(*(uint16_t*)p) & 0x3fff;
            isOffset = true;
            p = (void*)((char*)p + 2);
            break;
        }
        p = (void*)((char*)p + 1);
        p_out_of_range(p, end);
        labels.push_back(std::string((const char*)p, len));
        p = (void*)((char*)p + len);
    }
}
/// @brief 递归解析包中的偏移量作为下一个偏移量，直到得到一个非偏移量作为域名
/// @param packet DNS包
/// @param end DNS包的末尾
/// @note 已实现域名中出现部分偏移量的情况
void DomainName::parseOffset(void* packet, const void* end) {
    if (isOffset) {
        void* p = (char*)packet + offset;
        p_out_of_range(p, end);
        if (*(uint8_t*)p >> 6 == 0b11) {
            offset = ::ntohs(*(uint16_t*)p) & 0x3fff;
            parseOffset(packet, end);
        } else {
            isOffset = false;
            parseLabels(p, end);
        }
    }
}

std::string DomainName::toString() const {
    if (isOffset) {
        throw "isOffset";
    }
    std::string s;
    for (auto& label : labels) {
        s += label;
        s += '.';
    }
    s.pop_back();
    return s;
}

DNS_Base::DNS_Base(uint16_t transactionID, uint16_t flags, uint16_t questions,
                   uint16_t answerRRs, uint16_t authorityRRs,
                   uint16_t additionalRRs)
    : transactionID(transactionID),
      flags(flags),
      questions(questions),
      RRs({answerRRs, authorityRRs, additionalRRs}) {}

void DNS_Base::ntohs() {
    this->transactionID = ::ntohs(this->transactionID);
    this->flags = ::ntohs(this->flags);
    this->questions = ::ntohs(this->questions);
    for (auto& RR : RRs) {
        RR = ::ntohs(RR);
    }
}

DNS_Query::DNS_Query(void*& p, const void* end) : domainName(p, end) {
    p_out_of_range(p, end);
    CAST_AND_ADVANCE(queryType, p, end);
    CAST_AND_ADVANCE(queryClass, p);
    ntoh();
}
DNS_Query::DNS_Query(DomainName domainName, QueryType queryType,
                     uint16_t queryClass)
    : domainName(domainName), queryType(queryType), queryClass(queryClass) {}

void DNS_Query::ntoh() {
    this->queryType = QueryType(::ntohs(this->queryType));
    this->queryClass = ::ntohs(this->queryClass);
}

void DNS_Queries::addQuery(std::unique_ptr<DNS_Query>&& query) {
    queries.push_back(std::move(query));
}
const DNS_Queries::Queries& DNS_Queries::getQuereis() const { return queries; }
void DNS_Queries::display() const {
    printf("DNS Queries\n");
    for (auto& query : queries) {
        printf("   |-Domain Name       : %s\n",
               query->domainName.toString().c_str());
        printf("   |-Query Type        : %d\n", query->queryType);
        printf("   |-Query Class       : %d\n", query->queryClass);
        printf("\n");
    }
}
void DNS_Queries::parseDomainName(void* packet, const void* end) {
    for (auto& query : queries) {
        query->domainName.parseOffset(packet, end);
    }
}

DNS_Resource_Record::DNS_Resource_Record(void*& p, const void* end)
    : domainName(p, end) {
    p_out_of_range(p, end);
    CAST_AND_ADVANCE(queryType, p, end);
    CAST_AND_ADVANCE(queryClass, p, end);
    CAST_AND_ADVANCE(timeToLive, p, end);
    CAST_AND_ADVANCE(dataLen, p, end);
    ntoh();
    data = (const char*)p;
    p = (void*)((char*)p + dataLen);
}
DNS_Resource_Record::DNS_Resource_Record(DomainName domainName,
                                         QueryType queryType,
                                         uint16_t queryClass,
                                         uint32_t timeToLive, uint16_t dataLen,
                                         const char* data)
    : domainName(domainName),
      queryType(queryType),
      queryClass(queryClass),
      timeToLive(timeToLive),
      dataLen(dataLen),
      data(data) {}

bool DNS_Resource_Record::dataIsDomainName() const {
    switch (queryType) {
        case QueryType::CNAME:
        case QueryType::NS:
        case QueryType::SOA:
        case QueryType::PTR:
        case QueryType::MX:
            return true;
    }
    return false;
}
void DNS_Resource_Record::ntoh() {
    this->queryType = QueryType(::ntohs(this->queryType));
    this->queryClass = ::ntohs(this->queryClass);
    this->timeToLive = ::ntohl(this->timeToLive);
    this->dataLen = ::ntohs(this->dataLen);
}
std::string DNS_Resource_Record::dataToString() const {
    char buf[40];
    switch (queryType) {
        case QueryType::A:
            sprintf(buf, "%d.%d.%d.%d", (uint8_t)data[0], (uint8_t)data[1],
                    (uint8_t)data[2], (uint8_t)data[3]);
            return std::string(buf);
        case QueryType::AAAA:
            sprintf(buf,
                    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%"
                    "02x:%02x%02x:%02x%02x",
                    (uint8_t)data[0], (uint8_t)data[1], (uint8_t)data[2],
                    (uint8_t)data[3], (uint8_t)data[4], (uint8_t)data[5],
                    (uint8_t)data[6], (uint8_t)data[7], (uint8_t)data[8],
                    (uint8_t)data[9], (uint8_t)data[10], (uint8_t)data[11],
                    (uint8_t)data[12], (uint8_t)data[13], (uint8_t)data[14],
                    (uint8_t)data[15]);
            return std::string(buf);
        case QueryType::CNAME:
        case QueryType::NS:
        case QueryType::SOA:
        case QueryType::PTR:
        case QueryType::MX:
            return dataDomainName.toString();
        case QueryType::TXT:
        default:
            return std::string(data, dataLen);
    }
}

constexpr std::array<const char*, 3> DNS_RRs::type_s;
DNS_RRs::DNS_RRs(Type type) : type(type) {}
void DNS_RRs::addRR(std::unique_ptr<DNS_Resource_Record>&& record) {
    RRs.push_back(std::move(record));
}
const DNS_RRs::RRs_T& DNS_RRs::getRRs() const { return RRs; }
void DNS_RRs::display() const {
    printf("DNS %s\n", type_s[type]);
    for (auto& RR : RRs) {
        printf("   |-Domain Name       : %s\n",
               RR->domainName.toString().c_str());
        printf("   |-Query Type        : %d\n", RR->queryType);
        printf("   |-Query Class       : %d\n", RR->queryClass);
        printf("   |-Time To Live      : %d\n", RR->timeToLive);
        printf("   |-Data Length       : %d\n", RR->dataLen);
        printf("   |-Data              : %s\n", RR->dataToString().c_str());
        printf("\n");
    }
}
void DNS_RRs::parseDomainName(void* packet, const void* end) {
    for (auto& RR : RRs) {
        RR->domainName.parseOffset(packet, end);
        if (RR->dataIsDomainName()) {
            void* d = (void*)RR->data;
            RR->dataDomainName = DomainName(d, (char*)RR->data + RR->dataLen);
            RR->dataDomainName.parseOffset(packet, end);
        }
    }
}

DNS_Packet::DNS_Packet(void* packet, size_t packet_len)
    : RRs_3({DNS_RRs(DNS_RRs::ANSWER), DNS_RRs(DNS_RRs::AUTHORITY),
             DNS_RRs(DNS_RRs::ADDITIONAL)}) {
    if (packet_len < sizeof(DNS_Base)) {
        throw "p out of range";
    }
    this->base = (DNS_Base*)packet;
    this->base->ntohs();
    void* end = (void*)((char*)packet + packet_len);
    void* p = (void*)((char*)packet + sizeof(DNS_Base));
    for (int i = 0; i < base->questions; i++) {
        p_out_of_range(p, end);
        queries.addQuery(std::make_unique<DNS_Query>(p, end));
    }
    for (auto& RRs : RRs_3) {
        for (int i = 0; i < base->RRs[RRs.type]; i++) {
            p_out_of_range(p, end);
            RRs.addRR(std::make_unique<DNS_Resource_Record>(p, end));
        }
    }
}

void DNS_Packet::display() const {
    printf("DNS Packet\n");
    printf("   |-Transaction ID    : %d\n", base->transactionID);
    printf("   |-Flags             : %d\n", base->flags);
    printf("   |-Questions         : %d\n", base->questions);
    printf("   |-Answer RRs        : %d\n", base->RRs[0]);
    printf("   |-Authority RRs     : %d\n", base->RRs[1]);
    printf("   |-Additional RRs    : %d\n", base->RRs[2]);
    printf("\n");
    queries.display();
    for (const auto& RRs : RRs_3) {
        RRs.display();
    }
}

void DNS_Packet::parseDomainName(void* packet, const void* end) {
    queries.parseDomainName(packet, end);
    for (auto& RRs : RRs_3) {
        RRs.parseDomainName(packet, end);
    }
}
