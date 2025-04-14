#ifndef APSI_TESTS_H
#define APSI_TESTS_H

#include <openfhe.h>
#include <chrono>
#include "poly.h"
#include "HE.h"
#include "APSI_sender.h"
#include "hashing.h"

using namespace lbcrypto;

void testHashing();
void testPolyOps();
void testSender();
void testFullProtocolTwoParty(int numParties);
void testFullProtocol(uint32_t numParties, uint32_t numItem, bool isEncrypted);
void testPolyEvals();
void testIntersectionPoly();

#endif