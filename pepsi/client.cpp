#include "pepsi_client.h"
#include "pepsi_core.h"
#include "HE.h"

PEPSIQuery encryptClientData (
    HE &bfv,
    uint64_t data,
    uint32_t numCtxt,
    uint32_t kVal
) {
    std::vector<int64_t> msgVec = getCW(data, numCtxt, kVal);
    std::vector<Ciphertext<DCRTPoly>> payload(numCtxt);

    for (uint32_t i = 0;  i < numCtxt; i++) {
        std::vector<int64_t> _tmp(bfv.ringDim, msgVec[i]);
        Plaintext __tmp = bfv.packing(_tmp);
        payload[i] = bfv.encrypt(__tmp);
    }
    return PEPSIQuery {
        payload, numCtxt, kVal
    };
}


PEPSIQuery encryptClientDataPSI (
    HE &bfv,
    std::vector<int64_t> data,
    uint32_t numCtxt,
    uint32_t kVal
) {

    std::vector<int64_t> hashTable = computeCuckooHashTableClientPEPSI(
        data, bfv.ringDim, bfv.ringDim / 4096, -1
    );

    // Expand w.r.t. codewords
    std::vector<std::vector<int64_t>> msgVecs(numCtxt);
    for (auto &val : msgVecs) {
        val.resize(bfv.ringDim);
    }

    for (uint32_t i = 0; i < bfv.ringDim; i++) {
        std::vector<int64_t> _tmp = getCW(hashTable[i], numCtxt, kVal);

        for (uint32_t j = 0; j < numCtxt; j++) {
            msgVecs[j][i] = _tmp[j];
        }
    }
    std::vector<Ciphertext<DCRTPoly>> payload(numCtxt);

    for (uint32_t i = 0;  i < numCtxt; i++) {
        Plaintext __tmp = bfv.packing(msgVecs[i]);
        payload[i] = bfv.encrypt(__tmp);
    }
    
    return PEPSIQuery {
        payload, numCtxt, kVal
    };
}


bool checkIntResult (
    HE &bfv,
    Ciphertext<DCRTPoly> resCtxt
) {
    Plaintext ret = bfv.decrypt(resCtxt);
    std::vector<int64_t> retVec =  ret->GetPackedValue();
    // Check whether there is "1" in the received vector.
    for (int32_t i = 0; i < bfv.ringDim; i++) {
        if (retVec[i] == 1) {
            return 1;
        }
    }
    return 0;
}