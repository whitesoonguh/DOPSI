#include "vaf.h"

Ciphertext<DCRTPoly> ctxtMulByConstant(
    const Ciphertext<DCRTPoly> &x,
    int32_t val
) {
    Ciphertext<DCRTPoly> ret = x->Clone();
    std::vector<DCRTPoly> &cv = ret->GetElements();
    for (uint32_t i = 0; i < cv.size(); i++) {
        cv[i] = cv[i].Times(val);
    }   
    return ret;
}

void ctxtMulByConstantInPlace(
    Ciphertext<DCRTPoly> &x,
    int32_t val
) {
    std::vector<DCRTPoly> &cv = x->GetElements();
    for (uint32_t i = 0; i < cv.size(); i++) {
        cv[i] = cv[i].Times(val);
    }   
}


// VAF for p=2^16 + 1
Ciphertext<DCRTPoly> compVAF16(
    FHECTX &ctx,
    Ciphertext<DCRTPoly> &x,
    Plaintext ptOne
) {
    auto ret = x->Clone();
    for (uint32_t i = 0; i < 16; i++) {
        ctx.cc->EvalSquareInPlace(ret);
    }
    ctx.cc->EvalNegateInPlace(ret);
    ctx.cc->EvalAddInPlace(ret, ptOne);
    return ret;
}

// NPC
Ciphertext<DCRTPoly> compExactNPM(
    FHECTX &ctx,
    std::vector<Ciphertext<DCRTPoly>> &x,
    int32_t alpha
) {
    uint32_t k = x.size(); uint32_t isOdd;
    while (k > 1) {
        isOdd = k % 2;

        // Square
        for (uint32_t i = 0; i < k; i++) {
            ctx.cc->EvalSquareInPlace(x[i]);
        }
        // Multiply by Alpha 
        for (uint32_t i = 0; i < k/2; i++) {
            ctxtMulByConstantInPlace(x[2*i+1], alpha);
        }
        // Subtract
        for (uint32_t i = 0; i < k/2; i++) {
            x[i] = ctx.cc->EvalSub(x[2*i], x[2*i+1]);
        }        
        if (isOdd) {
            x[k/2] = x[k];
        }
        k >>=1;
        k += isOdd;
    }
    return x[0];
}

// Subroutine for Prob NPC
Ciphertext<DCRTPoly> randWSum(
    FHECTX &ctx,
    std::vector<Ciphertext<DCRTPoly>> &x
) {
    uint32_t numCtxts = x.size();

    // Randomness
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(1, ctx.modulus - 1);

    int64_t randNum;

    // std::vector<Ciphertext<DCRTPoly>> y(x.size());

    for (uint32_t i = 0; i < numCtxts; i++) {
        randNum = dist(gen);
        ctxtMulByConstantInPlace(x[i], randNum);
    }
    return ctx.cc->EvalAddMany(x);
}

// ProbNPC
Ciphertext<DCRTPoly> compProbNPM (
    FHECTX &ctx,
    std::vector<Ciphertext<DCRTPoly>> &x,
    int32_t alpha,
    uint32_t numRand
) {
    // Probabilistic Reduction
    std::vector<Ciphertext<DCRTPoly>> randCtxt(numRand);

    for (uint32_t i = 0; i < numRand; i++) {
        randCtxt[i] = randWSum(ctx, x);
    }
    return compExactNPM(ctx, randCtxt, alpha);
}