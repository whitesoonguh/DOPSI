#ifndef PEPSI_HASHING_H
#define PEPSI_HASHING_H

#include <iostream>
#include <cstdint>
#include <vector>
#include <openssl/sha.h>
#include <stdexcept>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "../core/utils.h"

std::vector<int64_t> computeCuckooHashTableClientPEPSI(
    std::vector<int64_t> &inputVec,
    uint32_t ringDim,
    uint32_t dimElem,
    int64_t dummyVal
);

std::vector<std::vector<int64_t>> computeCuckooHashTableServerPEPSI(
    std::vector<int64_t> inputVec,
    uint32_t ringDim,
    uint32_t maxBin,
    uint32_t dimElem,
    int64_t dummyVal,
    uint32_t h
);

#endif 