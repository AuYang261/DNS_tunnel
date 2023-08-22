#ifndef HEADERS_H
#define HEADERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

#include <array>

class DNS_Request {
   public:
    DNS_Request();
    ~DNS_Request();

    void setTransactionID(uint16_t transactionID);
    void setFlags(uint16_t flags);
    void setQuestions(uint16_t questions);
    void setAnswerRRs(uint16_t answerRRs);
    void setAuthorityRRs(uint16_t authorityRRs);
    void setAdditionalRRs(uint16_t additionalRRs);
    void setQueries(std::array<uint8_t, 256> queries);
    void setQueriesLength(uint16_t queriesLength);
    void setQueriesName(std::array<uint8_t, 256> queriesName);
    void setQueriesNameLength(uint16_t queriesNameLength);
    void setQueriesType(uint16_t queriesType);
    void setQueriesClass(uint16_t queriesClass);

    uint16_t getTransactionID();
    uint16_t getFlags();
    uint16_t getQuestions();
    uint16_t getAnswerRRs();
    uint16_t getAuthorityRRs();
    uint16_t getAdditionalRRs();
    std::array<uint8_t, 256> getQueries();
    uint16_t getQueriesLength();
    std::array<uint8_t, 256> getQueriesName();
    uint16_t getQueriesNameLength();
    uint16_t getQueriesType();
    uint16_t getQueriesClass();

   private:
    uint16_t transactionID;
    uint16_t flags;
    uint16_t questions;
    uint16_t answerRRs;
    uint16_t authorityRRs;
    uint16_t additionalRRs;
    std::array<uint8_t, 256> queries;
    uint16_t queriesLength;
    std::array<uint8_t, 256> queriesName;
    uint16_t queriesNameLength;
    uint16_t queriesType;
    uint16_t queriesClass;
};

#endif  // DNS_H