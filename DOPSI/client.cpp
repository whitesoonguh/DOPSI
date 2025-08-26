#include "client.h"

// DO-PMT
// Process Query

Ciphertext<DCRTPoly> queryCompress(
    FHECTX &ctx,
    std::vector<int64_t> data
) {
    uint32_t k = data.size();
    std::vector<int64_t> msgVec(ctx.ringDim);
    uint32_t numOnes = ctx.ringDim / k;

    // Pack consecutive values!
    for (uint32_t i = 0; i < ctx.ringDim; i++) {
        msgVec[i] = data[i/numOnes];
    }
    Plaintext ptxt = ctx.cc->MakePackedPlaintext(msgVec);
    return ctx.cc->Encrypt(ptxt, ctx.sk);
}


// DO-PSI
Ciphertext<DCRTPoly> queryCompressTable(
    FHECTX &ctx,
    std::vector<std::vector<int64_t>> data
) {
    // Make Hash Table; this it just a compressed table!
    std::vector<int64_t> msgVec = computeCuckooHashTableClient(
        data, ctx.ringDim, -1
    );

    Plaintext ptxt = ctx.cc->MakePackedPlaintext(msgVec);
    return ctx.cc->Encrypt(ptxt, ctx.sk);
}