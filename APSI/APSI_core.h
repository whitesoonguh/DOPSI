#ifndef APSI_CORE_H
#define APSI_CORE_H

#include <openfhe.h>
#include <random>
#include "HE.h"
#include "powers.h"


using namespace lbcrypto;

typedef struct _APSIParams {
    std::vector<uint32_t> pos;
    uint32_t itemLen;
    uint32_t maxBin;
    uint32_t ps_low_degree;
} APSIParams;

int64_t modPow(int64_t a, int64_t n, int64_t p);

void compute_all_powers(
    HE &bfv,
    const PowersDag &dag,
    std::vector<Ciphertext<DCRTPoly>> &powers
);

Ciphertext<DCRTPoly> PolyEvalLinearPtxt(
    HE &bfv,
    std::vector<Plaintext> coeffs,
    std::vector<Ciphertext<DCRTPoly>> powers
);

Ciphertext<DCRTPoly> PolyEvalLinearCtxt(
    HE &bfv,
    std::vector<Ciphertext<DCRTPoly>> coeffs,
    std::vector<Ciphertext<DCRTPoly>> powers
);

Ciphertext<DCRTPoly> PolyEvalPS(
    HE &bfv,
    std::vector<Plaintext> coeffs,
    std::vector<Ciphertext<DCRTPoly>> powers,
    uint32_t ps_low_degree
);

Plaintext makeRandomMask(
    HE &bfv
);

#endif 