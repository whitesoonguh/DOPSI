#ifndef HASHING_H
#define HASHING_H

#include "utils.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <openssl/sha.h>
#include <stdexcept>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/sha.h>

uint64_t computeHash(
    std::vector<int64_t> input, 
    uint32_t salt
);

std::vector<std::vector<int64_t>> computeHashTable(
    std::vector<std::vector<int64_t>> inputVec,
    uint32_t ringDim,
    uint32_t maxBin,
    int64_t dummyVal
);

std::vector<int64_t> computeCuckooHashTableClient(
    std::vector<std::vector<int64_t>> &inputVec,
    uint32_t ringDim,
    int64_t dummyVal
);

std::vector<std::vector<int64_t>> computeCuckooHashTableServer(
    std::vector<std::vector<int64_t>> inputVec,
    uint32_t ringDim,
    uint32_t maxBin,
    int64_t dummyVal,
    uint32_t h
);

#endif