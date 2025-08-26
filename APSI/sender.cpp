#include "APSI_sender.h"

APSIPtxtDB constructPtxtDB (
    HE &bfv,
    NTTContext ctx,
    std::vector<std::vector<int64_t>> hashTable,
    uint32_t maxDegree
) {
    // Segment hashTable into maxDegree
    uint32_t numBins = hashTable.size();
    uint32_t numItemsPerBin = hashTable[0].size();
    uint32_t numChunks = numItemsPerBin / maxDegree + (numItemsPerBin % maxDegree != 0);

    std::vector<APSIPtxtChunk> ptxtChunks(numChunks);

    for (uint32_t i = 0; i < numChunks; i++) {
        uint32_t start = i * maxDegree;
        uint32_t end = std::min((i + 1) * maxDegree, numItemsPerBin);

        std::vector<Plaintext> _payload(maxDegree + 1);
        std::vector<std::vector<int64_t>> _tmpMsgVec(numBins);
        
        // Parallel Interpolation
        #pragma omp parallel for
        for (uint32_t j = 0; j < numBins; j++) {
            std::vector<int64_t> currVec(hashTable[j].begin() + start, hashTable[j].begin() + end);

            // Do polynomial Interpolation
            currVec = constructInterPoly(ctx, currVec);

            if (currVec.size() < maxDegree + 1) {
                currVec.resize(maxDegree + 1, 0);
            }

            // Do Packing
            _tmpMsgVec[j] = currVec;
        }
        // Preparing each plaintexts
        // #pragma omp parallel for
        for (uint32_t j = 0; j < maxDegree + 1; j++) {
            std::vector<int64_t> _tmp(numBins); 
            for (uint32_t k = 0; k < numBins; k++) {
                _tmp[k] = _tmpMsgVec[k][j];
            }
            _payload[j] = bfv.packing(_tmp);
        }
        // Done!
        ptxtChunks[i] = APSIPtxtChunk { _payload, maxDegree};
    }
    return APSIPtxtDB { ptxtChunks, maxDegree };
}

APSICtxtDB constructCtxtDB (
    HE &bfv,
    NTTContext ctx,
    std::vector<std::vector<int64_t>> hashTable,
    uint32_t maxDegree
) {
    // Segment hashTable into maxDegree
    uint32_t numBins = hashTable.size();
    uint32_t numItemsPerBin = hashTable[0].size();
    uint32_t numChunks = numItemsPerBin / maxDegree + (numItemsPerBin % maxDegree != 0);

    std::vector<APSICtxtChunk> ctxtChunks(numChunks);

    for (uint32_t i = 0; i < numChunks; i++) {
        uint32_t start = i * maxDegree;
        uint32_t end = std::min((i + 1) * maxDegree, numItemsPerBin);

        std::vector<Ciphertext<DCRTPoly>> _payload(maxDegree + 1);
        std::vector<std::vector<int64_t>> _tmpMsgVec(numBins);
        
        // Parallel Interpolation
        #pragma omp parallel for
        for (uint32_t j = 0; j < numBins; j++) {
            std::vector<int64_t> currVec(hashTable[j].begin() + start, hashTable[j].begin() + end);

            // Do polynomial Interpolation
            currVec = constructInterPoly(ctx, currVec);

            if (currVec.size() < maxDegree + 1) {
                currVec.resize(maxDegree + 1, 0);
            }

            // Do Packing
            _tmpMsgVec[j] = currVec;
        }
        // Preparing each plaintexts
        // #pragma omp parallel for
        for (uint32_t j = 0; j < maxDegree + 1; j++) {
            std::vector<int64_t> _tmp(numBins); 
            for (uint32_t k = 0; k < numBins; k++) {
                _tmp[k] = _tmpMsgVec[k][j];
            }
            Plaintext _ptxt = bfv.packing(_tmp);
            _payload[j] = bfv.encrypt(_ptxt);
        }
        // Done!
        ctxtChunks[i] = APSICtxtChunk { _payload, maxDegree};
    }
    return APSICtxtDB { ctxtChunks, maxDegree };
}



Ciphertext<DCRTPoly> compInterChunkPtxt(
    HE &bfv,
    APSIPtxtChunk chunk,
    std::vector<Ciphertext<DCRTPoly>> powers,
    uint32_t ps_low_degree
) {
    // Do Paterson-Stockmeyer or Not?
    Ciphertext<DCRTPoly> ret;
    if (ps_low_degree == 0) {
        ret = PolyEvalLinearPtxt(bfv, chunk.payload, powers);
    } else {
        ret = PolyEvalPS(bfv, chunk.payload, powers, ps_low_degree);
    }

    // Random Masking
    Plaintext mask = makeRandomMask(bfv);
    ret = bfv.mult(ret, mask);
    return ret;
}

Ciphertext<DCRTPoly> compInterChunkCtxt(
    HE &bfv,
    APSICtxtChunk chunk,
    std::vector<Ciphertext<DCRTPoly>> powers,
    uint32_t ps_low_degree
) {
    // Do Paterson-Stockmeyer or Not?
    // Do Always Linear Evaluation
    Ciphertext<DCRTPoly> ret = PolyEvalLinearCtxt(bfv, chunk.payload, powers);

    // Random Masking
    Plaintext mask = makeRandomMask(bfv);
    ret = bfv.mult(ret, mask);
    return ret;
}


std::vector<Ciphertext<DCRTPoly>> compInterPtxt(
    HE &bfv,
    APSIParams params,
    APSIPtxtDB DB,
    APSIQuery query,
    uint32_t remDepth
) {
    // Query Expansion    
    PowersDag dag;
    std::set<uint32_t> target_powers;
    for (uint32_t i = 1; i < params.maxBin; i++) {
        target_powers.insert(i);
    }
    std::set<uint32_t> posSet(query.pos.begin(), query.pos.end());
    trim_sources(posSet, target_powers);
    bool isOK = dag.configure(posSet, target_powers);
    if (!isOK) {
        std::cout << "Something Went Wrong..." << std::endl;
    }

    std::vector<Ciphertext<DCRTPoly>> powers(params.maxBin);
    // Place Powers
    for (uint32_t i = 0; i < query.powers.size(); i++) {
        powers[query.pos[i] - 1] = query.powers[i];
    }
    compute_all_powers(bfv, dag, powers);

    // Do computation
    uint32_t numChunks = DB.payload.size();
    std::vector<Ciphertext<DCRTPoly>> ret(numChunks);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numChunks; i++) {
        ret[i] = compInterChunkPtxt(bfv, DB.payload[i], powers, params.ps_low_degree);
        ret[i] = bfv.compress(ret[i], remDepth);
    }

    // Optional: Compression
    return ret;
}

std::vector<Ciphertext<DCRTPoly>> compInterCtxt(
    HE &bfv,
    APSIParams params,
    APSICtxtDB DB,
    APSIQuery query,
    uint32_t remDepth
) {
    // Query Expansion    
    PowersDag dag;
    std::set<uint32_t> target_powers;
    for (uint32_t i = 1; i < params.maxBin; i++) {
        target_powers.insert(i);
    }
    std::set<uint32_t> posSet(query.pos.begin(), query.pos.end());
    trim_sources(posSet, target_powers);
    bool isOK = dag.configure(posSet, target_powers);
    if (!isOK) {
        std::cout << "Something Went Wrong..." << std::endl;
    }

    std::vector<Ciphertext<DCRTPoly>> powers(params.maxBin);
    // Place Powers
    for (uint32_t i = 0; i < query.powers.size(); i++) {
        powers[query.pos[i] - 1] = query.powers[i];
    }
    compute_all_powers(bfv, dag, powers);

    // Do computation
    uint32_t numChunks = DB.payload.size();
    std::vector<Ciphertext<DCRTPoly>> ret(numChunks);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numChunks; i++) {
        ret[i] = compInterChunkCtxt(bfv, DB.payload[i], powers, params.ps_low_degree);
        ret[i] = bfv.compress(ret[i], remDepth);
    }
    return ret;
}


std::vector<Ciphertext<DCRTPoly>> compAggResponse(
    HE &bfv,
    std::vector<std::vector<Ciphertext<DCRTPoly>>> responses
) {
    uint32_t numChunks = responses[0].size();
    uint32_t numParties = responses.size();
    std::vector<Ciphertext<DCRTPoly>> ret(numChunks);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numChunks; i++) {
        std::vector<Ciphertext<DCRTPoly>> _tmp(numParties);
        for (uint32_t j = 0; j < numParties; j++) {
            _tmp[j] = responses[j][i];
        }
        ret[i] = bfv.multmany(_tmp);
        ret[i] = bfv.compress(ret[i], 3);
    }
    return ret;
}