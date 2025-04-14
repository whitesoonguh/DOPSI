#include "hashing.h"

uint64_t computeHash(
    std::vector<int64_t> input, 
    uint32_t salt = 42
) {
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

    // Use EVP (Recommended for OpenSSL 3.x)
    EVP_MD_CTX* sha256 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256, EVP_sha256(), nullptr);
    EVP_DigestUpdate(sha256, &salt, sizeof(salt));

    for (uint64_t num : input) {
        EVP_DigestUpdate(sha256, &num, sizeof(num));
    }

    EVP_DigestFinal_ex(sha256, hash, nullptr);
    EVP_MD_CTX_free(sha256);  // Free the context

    uint64_t* result_ptr = reinterpret_cast<uint64_t*>(hash);
    return *result_ptr;
}

std::vector<std::vector<int64_t>> computeHashTable(
    std::vector<std::vector<int64_t>> inputVec,
    uint32_t ringDim,
    uint32_t maxBin,
    int64_t dummyVal
) {
    // Assume that the input vector is already pre-processed well.
    uint32_t dimElem = inputVec[0].size();
    uint32_t numBins = ringDim / dimElem;
    std::vector<std::vector<int64_t>> retTable(ringDim);
    std::vector<uint32_t> currItems(ringDim, 0);


    for (auto& innerVec: retTable) {
        innerVec.resize(maxBin, dummyVal);
    }        

    for (uint32_t i = 0; i < inputVec.size(); i++) {
        uint64_t ret = computeHash(inputVec[i], 42) % numBins;
        // Place values in an consecutive manner
        for (uint32_t j = 0; j < dimElem; j++) {
            uint32_t currIdx = ret * dimElem + j;
            
            retTable[currIdx][currItems[currIdx]] = inputVec[i][j];
            currItems[currIdx]++;
            if (currItems[currIdx] > maxBin) {
                throw std::runtime_error("Too many items in a bin");
            }
        }
    }

    uint32_t actualMaxBin = *std::max_element(currItems.begin(), currItems.end());

    // Trim the table
    for (auto& innerVec: retTable) {
        innerVec.resize(actualMaxBin);
    }        

    std::cout << "Actual Max Bin: " << actualMaxBin << std::endl;
    return retTable;
}
