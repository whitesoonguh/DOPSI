#ifndef DOPSI_SERVER_H
#define DOPSI_SERVER_H

#include "header.h"

struct DOPMTDB {
    std::vector<std::vector<Ciphertext<DCRTPoly>>> payload;
    Plaintext ptOne;
    std::vector<Plaintext> maskPtxts;
    int64_t alpha;
};

struct DOPMTServerResponse {
    Ciphertext<DCRTPoly> vafOutput;
    Ciphertext<DCRTPoly> maskCtxt;
};

DOPMTDB makeDOPMTDB (
    FHECTX &ctx,
    std::vector<std::vector<int64_t>> msgVecs,
    int64_t alpha
);

DOPMTDB makeDOPSIDB (
    FHECTX &ctx,
    std::vector<std::vector<int64_t>> &msgVecs,
    int64_t alpha
);

DOPMTServerResponse compInterPMTServer(
    FHECTX &ctx,
    DOPMTDB &DB,
    Ciphertext<DCRTPoly> &query,
    uint32_t mode
);

DOPMTServerResponse compInterPSIServer(
    FHECTX &ctx,
    DOPMTDB &DB,
    Ciphertext<DCRTPoly> &query,
    uint32_t mode
);

Ciphertext<DCRTPoly> compAggLeader (
    FHECTX &ctx,
    std::vector<DOPMTServerResponse> &responses
);

#endif 