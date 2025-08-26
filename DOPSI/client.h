#ifndef DOPSI_CLIENT_H
#define DOPSI_CLIENT_H

#include "header.h"

Ciphertext<DCRTPoly> queryCompress(
    FHECTX &ctx,
    std::vector<int64_t> data
);

Ciphertext<DCRTPoly> queryCompressTable(
    FHECTX &ctx,
    std::vector<std::vector<int64_t>> data
);

#endif