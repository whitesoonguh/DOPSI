#ifndef TEST_H
#define TEST_H

#include "HE.h"
#include "server.h"
#include "client.h"

// Main Test Functions
void testFullProtocol(
    uint64_t numItem,
    uint32_t lenData,
    uint32_t numPack,
    uint32_t numAgg,
    int32_t alpha,
    const std::string& interType,
    bool allowIntersection    
);

void testEncoding();
void testVAFs();
void testNPC();
void testBasicOPs();
void testRotAdd();
void testProbNPC(int k);
void testAgg(int numParties);
void testRotAgg(int numParties);
void testSanityCheck(int numParties);
void testAggCheck(int numParties);
void testVAFandAggCheck(int numParties);

void testAllBackends(int k, int numParties);

#endif