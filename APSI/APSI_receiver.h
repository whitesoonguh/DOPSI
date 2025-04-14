#ifndef APSI_RECEIVER_H
#define APSI_RECEIVER_H

#include <openfhe.h>
#include "APSI_core.h"
#include "hashing.h"
#include "HE.h"

using namespace lbcrypto;

typedef struct _APSIQuery {
    std::vector<Ciphertext<DCRTPoly>> powers;
    std::vector<uint32_t> pos;
} APSIQuery;

APSIQuery constructQuery(
    HE &bfv,
    APSIParams params,
    std::vector<int64_t> items
);

std::tuple<bool, int32_t, int32_t> findIntersection(
    HE &bfv,
    APSIParams params,
    std::vector<Ciphertext<DCRTPoly>> retCtxts
);

#endif 