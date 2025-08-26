#include "utils.h"

FHECTX initParams (
    uint32_t modulus,
    uint32_t depth,
    uint32_t scalingMod
) {
    CCParams<CryptoContextBFVRNS> params;
    params.SetPlaintextModulus(modulus);
    params.SetMultiplicativeDepth(depth);
    params.SetScalingModSize(scalingMod);
    params.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<int32_t> rotIdx;

    for (uint32_t i = 1; i < cc->GetRingDimension(); i*=2) {
        rotIdx.push_back(i);
    }
    cc->EvalRotateKeyGen(keys.secretKey, rotIdx);

    std::cout << params << std::endl;
    std::cout << "CTXT MODULUS: " 
              << std::log2(cc->GetModulus().ConvertToDouble())
              << "bits" << std::endl;
    return FHECTX {
        cc,
        keys.publicKey,
        keys.secretKey,
        cc->GetRingDimension(),
        modulus    
    };
}

size_t ctxtSize(Ciphertext<DCRTPoly>& ctxt) {
    size_t size = 0;
    for (auto& element : ctxt->GetElements()) {
      for (auto& subelements : element.GetAllElements()) {
        auto lenght = subelements.GetLength();
        size += lenght * sizeof(subelements[0]);
      }
    }
    return size;
};

std::vector<std::vector<int64_t>> genData(
    uint32_t numItem,
    uint32_t lenData,
    uint32_t bound
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(1, bound - 1);

    std::vector<std::vector<int64_t>> ret(numItem);
    
    for (uint32_t i = 0; i < numItem; i++) {
        std::vector<int64_t> _tmp(lenData);
        for (uint32_t j = 0; j < lenData; j++) {
            _tmp[j] = dist(gen);
        }
        ret[i] = _tmp;
    }
    return ret;
}

Ciphertext<DCRTPoly> ctxtRotAdd(
    FHECTX &ctx,
    Ciphertext<DCRTPoly> &x,
    uint32_t numAdj
) {
    auto ret = x->Clone();
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = 1; i < numAdj; i=i*2) {
        _tmp = ctx.cc->EvalRotate(ret, i);
        ctx.cc->EvalAddInPlace(ret, _tmp);
    }
    return ret;
}

Ciphertext<DCRTPoly> ctxtRotAddStride(
    FHECTX &ctx,
    Ciphertext<DCRTPoly> &x,
    uint32_t stride
) {
    auto ret = x->Clone();
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = stride; i < ctx.ringDim; i=i*2) {
        _tmp = ctx.cc->EvalRotate(ret, i);
        ctx.cc->EvalAddInPlace(ret, _tmp);
    }
    return ret;
}


Ciphertext<DCRTPoly> sumOverSlots(
    FHECTX &ctx,
    Ciphertext<DCRTPoly> &x
) {
    auto ret = x->Clone();
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = 1; i < ctx.ringDim; i=i*2) {
        _tmp = ctx.cc->EvalRotate(ret, i);
        ctx.cc->EvalAddInPlace(ret, _tmp);
    }
    return ret;
}

Ciphertext<DCRTPoly> makeRandCtxt (
    FHECTX &ctx
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, ctx.modulus - 1);

    std::vector<int64_t> msgVec(ctx.ringDim);
    for (uint32_t i = 0; i < ctx.ringDim; i++) {
        msgVec[i] = dist(gen);
    }
    Plaintext ptxt = ctx.cc->MakePackedPlaintext(msgVec);
    return ctx.cc->Encrypt(ptxt, ctx.sk);
}


// Bin Size = 4096; lambda=40
// Refer to the fomula in CLR17

std::vector<int64_t> _table_1024 = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,113,185,314,552,1001,1862,3528,6785,13190,25847
};

std::vector<int64_t> _table_2048 = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,113,185,314,552,1001,1862,3528,6785,13190,25847
};

std::vector<int64_t> _table_4096 = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,74,114,186,315,554,1004,1865,3533,6792,13199
};

uint32_t getMaxBins(
    uint32_t numBins,
    uint32_t logN
) {
    uint32_t ret = 0;

    switch (numBins) {
        default:
            break;
        case 1024:
            ret = _table_1024[logN];
            break;
        case 2048:
            ret = _table_2048[logN];
            break;
        case 4096:            
            ret = _table_4096[logN];
            break;
    };

    return ret;
}