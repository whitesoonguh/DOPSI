#ifndef APSI_SENDER_H
#define APSI_SENDER_H

#include <openfhe.h>
#include "APSI_core.h"
#include "APSI_receiver.h"
#include "poly.h"
#include "HE.h"
#include "powers.h"

using namespace lbcrypto;


typedef struct _APSIPtxtChunk {
    std::vector<Plaintext> payload;
    uint32_t polyDeg;
} APSIPtxtChunk;

typedef struct _APSICtxtChunk {
    std::vector<Ciphertext<DCRTPoly>> payload;
    uint32_t polyDeg;
} APSICtxtChunk;

typedef struct _APSIPtxtDB {
    std::vector<APSIPtxtChunk> payload;
    uint32_t polyDeg;
} APSIPtxtDB;

typedef struct _APSICtxtDB {
    std::vector<APSICtxtChunk> payload;
    uint32_t polyDeg;
} APSICtxtDB;

APSIPtxtDB constructPtxtDB (
    HE &bfv,
    NTTContext ctx,
    std::vector<std::vector<int64_t>> hashTable,
    uint32_t maxDegree
);

APSICtxtDB constructCtxtDB (
    HE &bfv,
    NTTContext ctx,
    std::vector<std::vector<int64_t>> hashTable,
    uint32_t maxDegree
);



std::vector<Ciphertext<DCRTPoly>> compInterPtxt(
    HE &bfv,
    APSIParams params,
    APSIPtxtDB DB,
    APSIQuery query,
    uint32_t remDepth
);

std::vector<Ciphertext<DCRTPoly>> compInterCtxt(
    HE &bfv,
    APSIParams params,
    APSICtxtDB DB,
    APSIQuery query,
    uint32_t remDepth
);

std::vector<Ciphertext<DCRTPoly>> compAggResponse(
    HE &bfv,
    std::vector<std::vector<Ciphertext<DCRTPoly>>> responses
);

#endif