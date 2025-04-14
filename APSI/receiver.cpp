#include "APSI_receiver.h"

// Query Ciphertext
APSIQuery constructQuery(
    HE &bfv,
    APSIParams params,
    std::vector<int64_t> items
) {
    // Useful Params
    uint32_t numPowers = params.pos.size();
    uint32_t prime = bfv.prime;
    uint32_t numItems = items.size();

    std::vector<std::vector<int64_t>> itemPowers(numPowers);

    for (uint32_t i = 0; i < numPowers; i++) {
        std::vector<int64_t> _tmp(numItems);
        for (uint32_t j = 0; j < numItems; j++) {
            _tmp[j] = modPow(items[j], params.pos[i], prime);
        }
        itemPowers[i] = _tmp;
    }

    // Hash Positions
    uint32_t numBins = bfv.ringDim / numItems;
    uint32_t pos = computeHash(items, 42) % numBins;

    std::vector<Ciphertext<DCRTPoly>> powers(numPowers);
    for (uint32_t i = 0; i < numPowers; i++) {
        std::vector<int64_t> _tmp(bfv.ringDim, -2);
        for (uint32_t j = 0; j < numItems; j++) {
            _tmp[pos + j] = itemPowers[i][j];
        }
        Plaintext ptxt = bfv.packing(_tmp);
        powers[i] = bfv.encrypt(ptxt);
    }

    return APSIQuery {powers, params.pos};
}

std::tuple<bool, int32_t> findConseqZeros(
    std::vector<int64_t> items,
    uint32_t stride
) {
    bool isFound = false; int32_t pos = -1;
    uint32_t numItem = items.size();
    for (uint32_t i = 0; i < numItem; i += stride) {
        bool _tmp = true; uint32_t offset = i * stride;
        for (uint32_t j = 0; j < stride; j++) {
            _tmp = _tmp && (items[offset + j] == 0);
        }

        if (_tmp) {
            isFound = true; pos = i;
        }
    }
    return std::tuple<bool, int32_t>(isFound, pos);
}


// Find Intersection
std::tuple<bool, int32_t, int32_t> findIntersection(
    HE &bfv,
    APSIParams params,
    std::vector<Ciphertext<DCRTPoly>> retCtxts
) {
    uint32_t itemLen = params.itemLen;
    uint32_t numCtxts = retCtxts.size();
    bool isFound = false;
    int32_t pos = -1; int32_t ctxtIdx = -1;
    for (uint32_t i = 0; i < numCtxts; i++) {
        std::vector<int64_t> retVal = bfv.decrypt(retCtxts[i])->GetPackedValue();
        auto _tmp = findConseqZeros(retVal, itemLen);

        if (get<0>(_tmp)) {
            isFound = true;
            pos = get<1>(_tmp); ctxtIdx = i;
        }
    }
    return std::tuple<bool, int32_t, int32_t>(isFound, pos, ctxtIdx);
}