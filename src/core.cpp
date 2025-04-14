#include "core.h"
#include "HE.h"
#include <openfhe.h>

using namespace lbcrypto;

// Compute NPCs
Ciphertext<DCRTPoly> compNPC (
    HE &bfv,
    std::vector<Ciphertext<DCRTPoly>> ctxts,
    Plaintext ptAlpha
) {
    int32_t numCtxts = ctxts.size();

    while (numCtxts > 1) {
        int32_t coin = numCtxts & 1;
        numCtxts -= coin;

        // Square
        for (int32_t i = 0; i < numCtxts; i++) {
            ctxts[i] = bfv.square(ctxts[i]);
        }

        // Multiply by Alpha
        for (int32_t i = 0; i < numCtxts / 2; i++) {
            ctxts[2 * i + 1] = bfv.mult(ctxts[2*i + 1], ptAlpha);
        }

        // Subtract
        for (int32_t i = 0; i < numCtxts / 2; i++) {
            ctxts[i] = bfv.sub(ctxts[2 * i], ctxts[2 * i + 1]);
        }

        // Finalize
        if (coin) {
            ctxts[numCtxts / 2] = ctxts[numCtxts];
        }
        
        numCtxts >>= 1;
        numCtxts += coin;
    }
    return ctxts[0];
}

// Compute VAF for p = 2^16 + 1
Ciphertext<DCRTPoly> compVAF16 (
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt,
    Plaintext ptOne
) {
    for (int i = 0; i < 16; i++) {
        ctxt = bfv.square(ctxt);
    }
    return bfv.sub(ptOne, ctxt);
}


// Compute VAF for a generic case
// Subroutine; prime should be larger than 0
std::vector<int32_t> bitDecomp(
    int32_t prime
) {
    std::vector<int32_t> ret;

    while (prime > 0) {
        ret.push_back(prime & 1);
        prime >>=1;
    }
    return ret;
}


// Main Function
Ciphertext<DCRTPoly> compVAF (
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt,
    int32_t prime,
    Plaintext ptOne
) {
    if (prime == 65537) {
        return compVAF16(bfv, ctxt, ptOne);
    } else {
        std::vector<int32_t> bits = bitDecomp(prime - 1);
        int32_t numBits = bits.size();

        Ciphertext<DCRTPoly> ret = ctxt;
        // Reversely Search
        for (int i = numBits - 2; i >= 0; i--) {
            ret = bfv.square(ret);
            if (bits[i]) {
                ret = bfv.mult(ret, ctxt);
            }
        }
        return bfv.sub(ptOne, ret);
    }    
}

// Rotate and Multiplication
Ciphertext<DCRTPoly> compRotMult(
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt,
    int32_t numPack
) {
    Ciphertext<DCRTPoly> ret = ctxt;
    Ciphertext<DCRTPoly> _tmp;

    // Do rotation and Mult
    for (int32_t i = 1; i < numPack; i*= 2) {
        _tmp = bfv.rotate(ret, i);
        ret = bfv.mult(ret, _tmp);
    }
    return ret;
}

// Rotate and Evaluate NPC
Ciphertext<DCRTPoly> compRotNPC(
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt,
    int32_t numPack,
    Plaintext ptAlpha
) {
    Ciphertext<DCRTPoly> ret = ctxt;
    Ciphertext<DCRTPoly> _tmp, __tmp;

    // Do Evaluate NPC
    for (int32_t i = 1; i < numPack; i*= 2) {
        _tmp = bfv.square(ret);
        __tmp = bfv.mult(_tmp, ptAlpha);
        __tmp = bfv.rotate(__tmp, i);
        ret = bfv.sub(_tmp, __tmp);
    }
    return ret;
}

// Random Linear Combination
Ciphertext<DCRTPoly> randWSum (
    HE &bfv,
    std::vector<Ciphertext<DCRTPoly>> ctxts
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, bfv.prime - 1);

    std::vector<Ciphertext<DCRTPoly>> retVec(ctxts.size());
    Ciphertext<DCRTPoly> ret, _tmp; 
    Plaintext _ptxt;
    int64_t randNum;

    // Parallelize   
    if (ctxts.size() >= 64) {
        #pragma omp parallel for private(randNum, _ptxt)
        for (uint32_t i = 0; i < ctxts.size(); i++) {
            randNum = dist(gen);
            std::vector<int64_t> randVec(bfv.ringDim, randNum);
            _ptxt = bfv.packing(randVec);
            retVec[i] = bfv.mult(ctxts[i], _ptxt);
        }
    } else {
        for (uint32_t i = 0; i < ctxts.size(); i++) {
            randNum = dist(gen);
            std::vector<int64_t> randVec(bfv.ringDim, randNum);
            _ptxt = bfv.packing(randVec);
            retVec[i] = bfv.mult(ctxts[i], _ptxt);
        }        
    }

    ret = bfv.addmany(retVec);
    return ret;
}

// Unsafe but probably faster version of multiplying random element
Ciphertext<DCRTPoly> randWSumInPlace(
    HE &bfv,
    const std::vector<Ciphertext<DCRTPoly>> ctxts
) {
    // Random Number Generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, bfv.prime - 1);

    // Setup for the return
    Ciphertext<DCRTPoly> ret, _tmp; 
    Plaintext _ptxt;
    int64_t randNum;

    // Parallel Computation
    if (ctxts.size() >= 16) {
        #pragma omp parallel for private(randNum, _ptxt)
        for (uint32_t i = 0; i < ctxts.size(); i++) {
            randNum = dist(gen);
            std::vector<DCRTPoly> &cv = ctxts[i]->GetElements();
            for (uint32_t j = 0; j < cv.size(); j++) {
                cv[j] = cv[j].Times(randNum);
            }
        }
    } else {
        for (uint32_t i = 0; i < ctxts.size(); i++) {
            randNum = dist(gen);
            std::vector<DCRTPoly> &cv = ctxts[i]->GetElements();
            for (uint32_t j = 0; j < cv.size(); j++) {
                cv[j] = cv[j].Times(randNum);
            }
        }        
    }    
    ret = bfv.addmany(ctxts);
    return ret;
}



// Probabilistic NPC
Ciphertext<DCRTPoly> compProbNPC(
    HE &bfv,
    std::vector<Ciphertext<DCRTPoly>> ctxts,    
    Plaintext ptAlpha,
    uint32_t numRand
) {
    // Run Probablistic NPC First
    std::vector<Ciphertext<DCRTPoly>> randVec(numRand);
    Ciphertext<DCRTPoly> ret, _tmp;

    for (uint32_t i = 0; i < numRand; i++) {
        randVec[i] = randWSumInPlace(bfv, ctxts);        
    }

    // Second: Run Original NPC
    ret = compNPC(bfv, randVec, ptAlpha);
    return ret;
}


// Utility Function for Creating a Random Masking Vector
Ciphertext<DCRTPoly> genRandCiphertext(
    HE &bfv,
    uint32_t numRand
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, bfv.prime - 1);
    
    std::vector<int64_t> randVec(numRand);

    for (uint32_t i = 0; i < numRand; i++) {
        randVec[i] = dist(gen);
    }

    std::vector<int64_t> msgVec(bfv.ringDim, 0);

    #pragma omp parallel for
    for (uint32_t i = 0; i < bfv.ringDim; i++) {
        msgVec[i] = randVec[i % numRand];        
    }

    Plaintext ptxt = bfv.packing(msgVec);
    return bfv.encrypt(ptxt);
}

// Utility Function for Summing Across All the Slots
Ciphertext<DCRTPoly> sumOverSlots(
    HE &bfv,
    Ciphertext<DCRTPoly> ctxt
) {
    Ciphertext<DCRTPoly> _tmp;
    Ciphertext<DCRTPoly> ret = ctxt->Clone();
    for (uint32_t i = 1; i < bfv.ringDim; i*=2) {
        _tmp = bfv.rotate(ret, i);
        ret = bfv.add(ret, _tmp);
    }
    return ret;
}