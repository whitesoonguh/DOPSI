#ifndef PEPSI_CLIENT_H
#define PEPSI_CLIENT_H

#include <openfhe.h>
#include "HE.h"

using namespace lbcrypto;

typedef struct _PEPSIQuery {
    std::vector<Ciphertext<DCRTPoly>> payload;
    uint32_t numCtxt;
    uint32_t kVal;
} PEPSIQuery;

PEPSIQuery encryptClientData(
    HE &bfv,
    uint64_t data,
    uint32_t numCtxt,
    uint32_t kVal
);

PEPSIQuery encryptClientDataPSI (
    HE &bfv,
    std::vector<int64_t> data,
    uint32_t numCtxt,
    uint32_t kVal
);

bool checkIntResult (
    HE &bfv,
    Ciphertext<DCRTPoly> resCtxt
);

#endif