#ifndef VAF_H
#define VAF_H

#include "utils.h"

Ciphertext<DCRTPoly> compVAF16(
    FHECTX &ctx,
    Ciphertext<DCRTPoly> &x,
    Plaintext ptOne
);

Ciphertext<DCRTPoly> compExactNPM(
    FHECTX &ctx,
    std::vector<Ciphertext<DCRTPoly>> &x,
    int32_t alpha
);

Ciphertext<DCRTPoly> compProbNPM(
    FHECTX &ctx,
    std::vector<Ciphertext<DCRTPoly>> &x,
    int32_t alpha,
    uint32_t numRand
);

#endif