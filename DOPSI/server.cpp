#include "server.h"

// Common Methods
std::vector<Plaintext> makeMaskPtxts (
    FHECTX &ctx,
    uint32_t k
) {
    std::vector<Plaintext> ret(k);
    uint32_t numOnes = ctx.ringDim / k;

    for (uint32_t i = 0; i < k; i++) {
        uint32_t offset = numOnes * i;
        std::vector<int64_t> _tmp(ctx.ringDim, 0);
        for (uint32_t j = 0; j < numOnes; j++) {
            _tmp[offset + j] = 1;
        }
        ret[i] = ctx.cc->MakePackedPlaintext(_tmp);
    }
    return ret;
}

std::vector<Ciphertext<DCRTPoly>> queryExtract(
    FHECTX & ctx,
    Ciphertext<DCRTPoly> &x,
    std::vector<Plaintext> maskVecs
 ) {
    uint32_t k = maskVecs.size();
    std::vector<Ciphertext<DCRTPoly>> ret(k);
    uint32_t stride = ctx.ringDim / k;

    #pragma omp parallel for
    for (uint32_t i = 0; i < k; i++) {
        // Multiply Mask
        Ciphertext<DCRTPoly> _tmp = ctx.cc->EvalMult(x, maskVecs[i]);
        // RotAdd
        ret[i] = ctxtRotAddStride(ctx, _tmp, stride);
    }
    return ret;
}


// DO-PMT
// Process Database
DOPMTDB makeDOPMTDB (
    FHECTX &ctx,
    std::vector<std::vector<int64_t>> msgVecs,
    int64_t alpha
) {
    uint32_t numItems = msgVecs.size();
    uint32_t kVal = msgVecs[0].size();
    uint32_t numChunks = numItems / ctx.ringDim + (numItems % ctx.ringDim != 0);

    std::vector<std::vector<Ciphertext<DCRTPoly>>> payload(numChunks);

    // Make Encrypted Database
    for (uint32_t i = 0; i < numChunks; i++) {
        uint32_t offset = i * ctx.ringDim;
        std::vector<Ciphertext<DCRTPoly>> _tmp(kVal);

        // Read Data
        for (uint32_t j = 0; j < kVal; j++) {
            std::vector<int64_t> _tmpMsg(ctx.ringDim, -1);

            for (uint32_t k = 0; k < ctx.ringDim; k++) {
                if (offset + k < numItems) {
                    _tmpMsg[k] = msgVecs[offset + k][j];
                }
            }
            Plaintext _ptxt = ctx.cc->MakePackedPlaintext(_tmpMsg);
            _tmp[j] = ctx.cc->Encrypt(_ptxt, ctx.pk);
        }
        payload[i] = _tmp;
    }

    std::vector<Plaintext> maskPtxts = makeMaskPtxts(ctx, kVal);
    Plaintext ptOne = ctx.cc->MakePackedPlaintext(std::vector<int64_t>(1, ctx.ringDim));

    return DOPMTDB {
        payload, ptOne, maskPtxts, alpha
    };
}

// DOPSI
DOPMTDB makeDOPSIDB (
    FHECTX &ctx,
    std::vector<std::vector<int64_t>> &msgVecs,
    int64_t alpha
) {
    uint32_t numItems = msgVecs.size();
    uint32_t kVal = msgVecs[0].size();

    uint32_t logN = std::log2(numItems);
    uint32_t maxBin = getMaxBins(ctx.ringDim / kVal,  logN);

    // Make Hash Table
    std::vector<std::vector<int64_t>> hashTable = computeCuckooHashTableServer (
        msgVecs, ctx.ringDim, maxBin, -1, 3
    );

    uint32_t numBuckets = hashTable.size();
    uint32_t numChunks = maxBin / kVal + (maxBin % kVal != 0);

    std::vector<std::vector<Ciphertext<DCRTPoly>>> payload(numChunks);

    // Make Encrypted Database
    for (uint32_t i = 0; i < numChunks; i++) {
        uint32_t offset = i * kVal;
        std::vector<Ciphertext<DCRTPoly>> _tmp(kVal);

        for (uint32_t j = 0; j < kVal; j++) {
            std::vector<int64_t> _tmpMsg(ctx.ringDim, -1);
            uint32_t coloffset = numBuckets * j;

            // Read Table
            for (uint32_t k = 0; k < kVal; k++) {
                for (uint32_t l = 0; l < numBuckets; l++) {
                    size_t idx = k * numBuckets + l;
                    if (idx < _tmpMsg.size() && offset + l < hashTable.size()) {
                        if (coloffset + k < hashTable[offset + l].size()) {
                            _tmpMsg[idx] = hashTable[offset + l][coloffset + k];
                        }
                    }
                }
            }
            Plaintext _ptxt = ctx.cc->MakePackedPlaintext(_tmpMsg);
            _tmp[j] = ctx.cc->Encrypt(_ptxt, ctx.pk);
        }
        payload[i] = _tmp;
    }

    std::vector<Plaintext> maskPtxts = makeMaskPtxts(ctx, kVal);
    Plaintext ptOne = ctx.cc->MakePackedPlaintext(std::vector<int64_t>(1, ctx.ringDim));

    return DOPMTDB {
        payload, ptOne, maskPtxts, alpha
    };    
}

// Do Server Operations

Ciphertext<DCRTPoly> compInterServerInner (
    FHECTX &ctx,
    std::vector<Ciphertext<DCRTPoly>> &x,
    std::vector<Ciphertext<DCRTPoly>> &y,
    Plaintext ptOne,
    int64_t alpha,
    uint32_t mode
) {
    uint32_t k = x.size();

    for (uint32_t i = 0; i < k; i++) {
        ctx.cc->EvalSubInPlace(x[i], y[i]);
    }

    Ciphertext<DCRTPoly> ret;

    // VAF with Exact NPC
    if (mode == 0) {
        ret = compExactNPM(ctx, x, alpha);
        ret = compVAF16(ctx, ret, ptOne);
    }
    else if (mode == 1) {
        ret = compProbNPM(ctx, x, alpha, 4);
        ret = compVAF16(ctx, ret, ptOne);
    }
    return ret;
}


DOPMTServerResponse compInterPMTServer(
    FHECTX &ctx,
    DOPMTDB &DB,
    Ciphertext<DCRTPoly> &query,
    uint32_t mode
) {
    uint32_t numChunks = DB.payload.size();

    // Extract Query
    std::vector<Ciphertext<DCRTPoly>> extQuery = queryExtract(
        ctx, query, DB.maskPtxts
    );

    // Do Calculations
    std::vector<Ciphertext<DCRTPoly>> vafRets(numChunks);
    #pragma omp parallel for
    for (uint32_t i = 0; i < numChunks; i++) {
        vafRets[i] = compInterServerInner(
            ctx, DB.payload[i], extQuery, DB.ptOne, DB.alpha, mode
        );
    }

    // Aggregate & Compress 
    Ciphertext<DCRTPoly> vafOutput = ctx.cc->EvalAddMany(vafRets);
    vafOutput = ctx.cc->Compress(vafOutput, 3);

    vafOutput = sumOverSlots(ctx, vafOutput);

    // Make Mask Randomness
    Ciphertext<DCRTPoly> maskCtxt = makeRandCtxt(ctx);
    maskCtxt = ctx.cc->Compress(maskCtxt, 3);

    return DOPMTServerResponse {
        vafOutput, maskCtxt
    };
}

// DO-PSI Server's Operations
DOPMTServerResponse compInterPSIServer(
    FHECTX &ctx,
    DOPMTDB &DB,
    Ciphertext<DCRTPoly> &query,
    uint32_t mode
) {
    uint32_t numChunks = DB.payload.size();

    // Extract Query
    std::vector<Ciphertext<DCRTPoly>> extQuery = queryExtract(
        ctx, query, DB.maskPtxts
    );
    uint32_t k = extQuery.size();

    // Do Calculations
    std::vector<Ciphertext<DCRTPoly>> vafRets(numChunks);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numChunks; i++) {
        vafRets[i] = compInterServerInner(
            ctx, DB.payload[i], extQuery, DB.ptOne, DB.alpha, mode
        );
    }

    // Aggregate & Compress 
    Ciphertext<DCRTPoly> vafOutput = ctx.cc->EvalAddMany(vafRets);
    vafOutput = ctx.cc->Compress(vafOutput, 3);
    vafOutput = ctxtRotAddStride(ctx, vafOutput, ctx.modulus / k);

    // Make Mask Randomness
    Ciphertext<DCRTPoly> maskCtxt = makeRandCtxt(ctx);
    maskCtxt = ctx.cc->Compress(maskCtxt, 3);

    return DOPMTServerResponse {
        vafOutput, maskCtxt
    };
}

// Leader Server
Ciphertext<DCRTPoly> compAggLeader (
    FHECTX &ctx,
    std::vector<DOPMTServerResponse> &responses
) {
    uint32_t numResponses = responses.size();
    std::vector<Ciphertext<DCRTPoly>> vafOuts(numResponses);
    std::vector<Ciphertext<DCRTPoly>> masks(numResponses);

    for (uint32_t i = 0; i < numResponses; i++) {
        vafOuts[i] = responses[i].vafOutput;
        masks[i] = responses[i].maskCtxt;
    }
    Ciphertext<DCRTPoly> vafAgg = ctx.cc->EvalAddMany(vafOuts);
    Ciphertext<DCRTPoly> maskAgg = ctx.cc->EvalAddMany(masks);

    return ctx.cc->EvalMult(vafAgg, maskAgg);
}
