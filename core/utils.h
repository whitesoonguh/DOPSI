#ifndef UTILS_H
#define UTILS_H

#include "openfhe.h"
using namespace lbcrypto;

struct FHECTX {
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    uint32_t ringDim;
    uint32_t modulus;
};

FHECTX initParams (
    uint32_t modulus,
    uint32_t depth,
    uint32_t scalingMod
);

size_t ctxtSize(Ciphertext<DCRTPoly>& ctxt);

std::vector<std::vector<int64_t>> genData(
    uint32_t numItem,
    uint32_t lenData,
    uint32_t bound
);

Ciphertext<DCRTPoly> ctxtRotAdd(
    FHECTX &ctx,
    Ciphertext<DCRTPoly> &x,
    uint32_t numAdj
);

Ciphertext<DCRTPoly> sumOverSlots(
    FHECTX &ctx,
    Ciphertext<DCRTPoly> &x
);


Ciphertext<DCRTPoly> makeRandCtxt (
    FHECTX &ctx
);

Ciphertext<DCRTPoly> ctxtRotAddStride(
    FHECTX &ctx,
    Ciphertext<DCRTPoly> &x,
    uint32_t stride
);

uint32_t getMaxBins(
    uint32_t numBins,
    uint32_t logN
);

#endif

