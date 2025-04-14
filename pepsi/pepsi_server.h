#ifndef PEPSI_SERVER
#define PEPSI_SERVER

#include <openfhe.h>
#include <vector>
#include "pepsi_client.h"

using namespace lbcrypto;

typedef struct _PEPSIChunk {
    std::vector<Ciphertext<DCRTPoly>> payload;
    uint32_t numCtxt;
    uint32_t kVal;
} PEPSIChunk;

typedef struct _PEPSIPtxtChunk {
    std::vector<Plaintext> payload;
    uint32_t numCtxt;
    uint32_t kVal;
} PEPSIPtxtChunk;

typedef struct _PEPSIDB {
    std::vector<PEPSIChunk> chunks;
    std::vector<PEPSIPtxtChunk> ptxtChunks;
    uint32_t numChunks;
    Plaintext ptDiv;
    uint32_t numCtxt;
    uint32_t kVal;
    bool isEncrypted;
} PEPSIDB;


typedef struct _ResponsePEPSIServer {
    Ciphertext<DCRTPoly> isInter;
    Ciphertext<DCRTPoly> maskVal;
} ResponsePEPSIServer;


PEPSIDB constructPEPSIDB (
    HE &bfv,
    std::vector<uint64_t> dataVec,
    uint32_t numCtxt,
    uint32_t kVal,   
    bool isEncrypted
);

ResponsePEPSIServer compPEPSIInter(
    HE &bfv,
    PEPSIQuery query,
    PEPSIDB DB
);



#endif