#ifndef APSI_HASHING_H
#define APSI_HASHING_H

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


#endif