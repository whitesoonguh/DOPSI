#include "HE.h"
#include "pepsi_server.h"
#include "pepsi_client.h"
#include "pepsi_core.h"

using namespace lbcrypto;

PEPSIDB constructPEPSIDB (
    HE &bfv,
    std::vector<int64_t> dataVec,
    uint32_t numCtxt,
    uint32_t kVal,   
    bool isEncrypted
) {
    uint32_t numData = dataVec.size();
    std::vector<std::vector<int64_t>> cwVec(numData);

    std::vector<std::vector<uint64_t>> table = chooseTable(numCtxt);

    #pragma omp parallel for 
    for (uint32_t i = 0; i < numData; i++) {
        cwVec[i] = getCWTable(dataVec[i], numCtxt, kVal, table);
    }

    // Encode Data w.r.t components
    uint32_t numChunks = (numData / bfv.ringDim) + (numData % bfv.ringDim != 0);
    std::vector<PEPSIChunk> chunks(numChunks);
    std::vector<PEPSIPtxtChunk> ptchunks(numChunks);
    Plaintext _ptxt; Ciphertext<DCRTPoly> _ctxt;

    // Make Chunks 
    for (uint32_t i = 0; i < numChunks; i++) {
        std::vector<Ciphertext<DCRTPoly>> payload(numCtxt);
        std::vector<Plaintext> ptpayload(numCtxt);
        uint32_t offset = i * bfv.ringDim;
        for (uint32_t j = 0; j < numCtxt; j++) {
            std::vector<int64_t> _tmp(bfv.ringDim, 0);
            for (uint32_t k = 0; k < bfv.ringDim; k++) {
                _tmp[i] = cwVec[offset + k][j];
            }   
            _ptxt = bfv.packing(_tmp);
            _ctxt = bfv.encrypt(_ptxt);
            payload[j] = _ctxt;
            ptpayload[j] = _ptxt;
        }
        PEPSIChunk chunk {
            payload, numCtxt, kVal
        };
        PEPSIPtxtChunk ptchunk {
            ptpayload, numCtxt, kVal
        };
        chunks[i] = chunk;
        ptchunks[i] = ptchunk;
    }

    // Compute ptDiv
    // This corresponds to (k-1)!
    int64_t divVal = 1;
    for (int64_t i = 1; i < (int64_t)kVal; i++) {
        divVal *= i;
        divVal = divVal % bfv.prime;
    }
    std::vector<int64_t> ptVec(bfv.ringDim, divVal);
    Plaintext ptDiv = bfv.packing(ptVec);

    return PEPSIDB {
        chunks, ptchunks, 
        numChunks, ptDiv, numCtxt, kVal, 
        isEncrypted
    };
}

PEPSIDB constructPEPSIDBPSI (
    HE &bfv,
    std::vector<int64_t> dataVec,
    uint32_t numCtxt,
    uint32_t kVal,   
    bool isEncrypted
) {
    // uint32_t numData = dataVec.size();
    // std::vector<std::vector<int64_t>> cwVec(numData);

    // std::vector<std::vector<uint64_t>> table = chooseTable(numCtxt);

    uint32_t maxBins = getMaxBins(4096, (int)std::log2(dataVec.size()));
    uint32_t dimElem = bfv.ringDim / 4096;

    std::vector<std::vector<int64_t>> hashTable = computeCuckooHashTableServerPEPSI(
        dataVec, bfv.ringDim, maxBins, dimElem, 42, 3
    );

    // Reshape Table First
    uint32_t numTotalBlocks = (maxBins / dimElem) + (maxBins % dimElem != 0);

    std::vector<std::vector<int64_t>> reHashTable(numTotalBlocks);
    for (auto &val : reHashTable) {
        val.resize(bfv.ringDim, 42);
    }


    #pragma omp parallel for 
    for (uint32_t i = 0; i < numTotalBlocks; i++) {
        uint32_t offset = i * dimElem;
        for (uint32_t j = 0; j < bfv.ringDim; j++) {
            uint32_t rowIdx = j % 4096;
            uint32_t colIdx = j / 4096;
            if (offset + colIdx < maxBins) {
                reHashTable[i][j] = hashTable[offset + colIdx][rowIdx];
            }
        }
    }



    // MAke DB Chunks
    std::vector<PEPSIChunk> chunks(numTotalBlocks);   
    std::vector<PEPSIPtxtChunk> ptchunks(numTotalBlocks);   

    std::vector<std::vector<uint64_t>> table = chooseTable(numCtxt);


    for (uint32_t i = 0; i < numTotalBlocks; i++) {
        std::vector<std::vector<int64_t>> msgVecs(numCtxt);

        for (auto &val : msgVecs) {
            val.resize(bfv.ringDim, 42);
        }

        // #pragma omp parallel for shared(table)
        for (uint32_t j = 0; j < bfv.ringDim; j++) {
            std::vector<int64_t> _tmp = getCWTable(reHashTable[i][j], numCtxt, kVal, table);

            for (uint32_t k = 0; k < numCtxt; k++) {
                msgVecs[k][j] = _tmp[k];
            }
        }

        std::cout << "YAY" << std::endl;

        // Make Ciphertexts
        std::vector<Ciphertext<DCRTPoly>> payload(numCtxt);
        std::vector<Plaintext> ptpayload(numCtxt);

        for (uint32_t j = 0;  j < numCtxt; j++) {
            Plaintext __tmp = bfv.packing(msgVecs[j]);
            ptpayload[j] = __tmp;
            payload[j] = bfv.encrypt(__tmp);
        }        
        chunks[i] = PEPSIChunk {
            payload, numCtxt, kVal
        };        
        ptchunks[i] = PEPSIPtxtChunk {
            ptpayload, numCtxt, kVal
        };
    }

    // Compute ptDiv
    // This corresponds to (k-1)!
    int64_t divVal = 1;
    for (int64_t i = 1; i < (int64_t)kVal; i++) {
        divVal *= i;
        divVal = divVal % bfv.prime;
    }
    std::vector<int64_t> ptVec(bfv.ringDim, divVal);
    Plaintext ptDiv = bfv.packing(ptVec);

    return PEPSIDB {
        chunks, ptchunks, 
        numTotalBlocks, ptDiv, numCtxt, kVal, 
        isEncrypted
    };
}



ResponsePEPSIServer compPEPSIInter(
    HE &bfv,
    PEPSIQuery query,
    PEPSIDB DB
) {     
    uint32_t numChunks = DB.numChunks;
    std::vector<Ciphertext<DCRTPoly>> retVec(numChunks);

    if (DB.isEncrypted) {
        #pragma omp parallel for
        for (uint32_t i = 0; i < numChunks; i++) {
            retVec[i] = arithCWEQ(
                bfv, query.payload, DB.chunks[i].payload, 
                DB.ptDiv, DB.kVal
            );
        }
    } else {
        #pragma omp parallel for
        for (uint32_t i = 0; i < numChunks; i++) {
            retVec[i] = arithCWEQPtxt(
                bfv, query.payload, DB.ptxtChunks[i].payload, 
                DB.ptDiv, DB.kVal
            );
        }
    }

    // Do Additive Aggregation
    Ciphertext<DCRTPoly> ret = bfv.addmany(retVec);

    // Compute Random Mask
    Ciphertext<DCRTPoly> maskVal = genRandCiphertext(bfv, NUM_RAND_MASKS);

    // Compress ALL
    ret = bfv.compress(ret, 3);
    maskVal = bfv.compress(maskVal, 3);

    // Done!
    return ResponsePEPSIServer { ret, maskVal };
}