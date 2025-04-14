#ifndef PEPSI_TEST_H
#define PEPSI_TEST_H

#include <openfhe.h>
#include "HE.h"
#include "pepsi_server.h"
#include "pepsi_client.h"
#include "pepsi_core.h"
#include <chrono>

void testPEPSIProtocol(
    uint32_t numItem,
    uint32_t bitlen,
    uint32_t HW,
    bool isEncrypted
);


#endif