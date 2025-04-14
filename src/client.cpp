#include <openfhe.h>
#include "HE.h"
#include "core.h"
#include "client.h"

using namespace lbcrypto;

// Encodes single ciphertext
std::vector<int64_t> encodeDataClient (
    const std::vector<uint32_t> &dataVec,
    int64_t prime
) {
    int32_t logp = (int)(std::log2(prime));
    int32_t lenData = dataVec.size();
    int32_t expRate = 32 / logp + ((32 % logp) != 0);
    int64_t mask = (int64_t(1)<<logp) - 1;

    std::vector<int64_t> ret;
    for (int32_t i = 0; i < expRate * lenData; i++) {
        uint32_t itemIdx = i / expRate;
        uint32_t lkupIdx = i % expRate;
        uint32_t currVal = dataVec[itemIdx] >> (logp * lkupIdx);
        ret.push_back((currVal & mask));
    }
    return ret;
}

Ciphertext<DCRTPoly> encryptQuery(
    HE &bfv,
    std::vector<int64_t> dataPrepared
) {
    uint32_t lenData = dataPrepared.size();
    std::vector<int64_t> payload(bfv.ringDim, 0);

    for (uint32_t i = 0; i < bfv.ringDim; i++) {
        payload[i] = dataPrepared[ i % lenData];
    }
    Plaintext tmp = bfv.packing(payload);
    return bfv.encrypt(tmp);
}

bool checkIntResult (
    HE &bfv,
    Ciphertext<DCRTPoly> resCtxt
) {
    Plaintext ret = bfv.decrypt(resCtxt);
    std::vector<int64_t> retVec =  ret->GetPackedValue();
    // Check whether there is "1" in the received vector.
    for (int32_t i = 0; i < bfv.ringDim; i++) {
        if (retVec[i] == 1) {
            return 1;
        }
    }
    return 0;
}


bool checkIntResultFromAgg(
    HE &bfv,
    Ciphertext<DCRTPoly> resCtxt
)  {
    Plaintext ret = bfv.decrypt(resCtxt);
    std::vector<int64_t> retVec =  ret->GetPackedValue();
    bool flag = false;
    for (uint32_t i = 0; i < NUM_RAND_MASKS; i++) {
        if (retVec[i] != 0) {
            return true;
        }
    }
    return flag;
}