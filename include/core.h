#ifndef CORE_H
#define CORE_H

#include "HE.h"
#include "openfhe.h"

using namespace lbcrypto;

Ciphertext<DCRTPoly> compNPC (
    HE &bfv,
    std::vector<Ciphertext<DCRTPoly>> ctxts,
    Plaintext ptAlpha
);

Ciphertext<DCRTPoly> compVAF16 (
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt,
    Plaintext ptOne
);

std::vector<int32_t> bitDecomp(
    int32_t prime
);

Ciphertext<DCRTPoly> compVAF (
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt,
    int32_t prime,
    Plaintext ptOne
);

Ciphertext<DCRTPoly> compRotMult(
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt,
    int32_t numPack
);

Ciphertext<DCRTPoly> compRotNPC(
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt,
    int32_t numPack,
    Plaintext ptAlpha
);

Ciphertext<DCRTPoly> randWSum (
    HE &bfv,
    std::vector<Ciphertext<DCRTPoly>> ctxts
);

Ciphertext<DCRTPoly> compProbNPC(
    HE &bfv,
    std::vector<Ciphertext<DCRTPoly>> ctxts,    
    Plaintext ptAlpha,
    uint32_t numRand
);

Ciphertext<DCRTPoly> randWSumInPlace(
    HE &bfv,
    const std::vector<Ciphertext<DCRTPoly>> ctxts
);

Ciphertext<DCRTPoly> genRandCiphertext(
    HE &bfv,
    uint32_t numRand
);

#endif