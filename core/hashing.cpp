#include "hashing.h"

uint64_t computeHash(
    std::vector<int64_t> input, 
    uint32_t salt = 42
) {
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

    // Use EVP (Recommended for OpenSSL 3.x)
    EVP_MD_CTX* sha256 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256, EVP_sha256(), nullptr);
    EVP_DigestUpdate(sha256, &salt, sizeof(salt));

    for (uint64_t num : input) {
        EVP_DigestUpdate(sha256, &num, sizeof(num));
    }

    EVP_DigestFinal_ex(sha256, hash, nullptr);
    EVP_MD_CTX_free(sha256);  // Free the context

    uint64_t* result_ptr = reinterpret_cast<uint64_t*>(hash);
    return *result_ptr;
}

std::vector<std::vector<int64_t>> computeHashTable(
    std::vector<std::vector<int64_t>> inputVec,
    uint32_t ringDim,
    uint32_t maxBin,
    int64_t dummyVal
) {
    // Assume that the input vector is already pre-processed well.
    uint32_t dimElem = inputVec[0].size();
    uint32_t numBins = ringDim / dimElem;
    std::vector<std::vector<int64_t>> retTable(ringDim);
    std::vector<uint32_t> currItems(ringDim, 0);

    std::cout << "Max Bin: " << maxBin << std::endl;

    for (auto& innerVec: retTable) {
        innerVec.resize(maxBin, dummyVal);
    }        

    for (uint32_t i = 0; i < inputVec.size(); i++) {
        uint64_t ret = computeHash(inputVec[i], 42) % numBins;

        // Place values with Jumps!
        for (uint32_t j = 0; j < dimElem; j++) {
            uint32_t currIdx = ret + numBins * j;
            
            retTable[currIdx][currItems[currIdx]] = inputVec[i][j];
            currItems[currIdx]++;
            if (currItems[currIdx] > maxBin) {
                throw std::runtime_error("Too many items in a bin");
            }
        }
    }

    uint32_t actualMaxBin = *std::max_element(currItems.begin(), currItems.end());

    // Trim the table
    for (auto& innerVec: retTable) {
        innerVec.resize(actualMaxBin);
    }        

    std::cout << "Actual Max Bin: " << actualMaxBin << std::endl;
    return retTable;
}

// Cuckoo Hashing

// A single bin entry
struct BinEntry {
    std::vector<int64_t> value;
    int32_t loc; // which hash function index
    bool isEmpty;
    BinEntry(std::vector<int64_t> v = std::vector<int64_t>(42, -1), int32_t l=-1): value(v), loc(l), isEmpty(true) {}
};

// Insert with recursive cuckoo hashing
bool Insert(
    std::vector<BinEntry>& bins,
    std::vector<int64_t> w,
    int32_t i,
    uint32_t m,                 // number of bins
    uint32_t h,                 // number of hash functions
    uint32_t depthLimit=10    // recursion limit
) {
    if (depthLimit == 0) return false; // fail if too deep

    // location function = hash with salt=i
    uint32_t pos = computeHash(w, i) % m;

    // swap (w,i) with current entry
    BinEntry tmp = bins[pos];
    bins[pos] = BinEntry(w, i);
    bins[pos].isEmpty = false;

    // if displaced item is empty, done
    if (tmp.isEmpty) {
        return true;
    }

    // otherwise, recurse with displaced item, but pick a new hash function j != tmp.loc
    for (uint32_t j = 0; j < h; j++) {
        if (j == (uint32_t)tmp.loc) continue;
        if (Insert(bins, tmp.value, j, m, h, depthLimit-1)) {
            return true;
        }
    }
    return false;
}

// Receiver side: insert Y into cuckoo table
std::vector<BinEntry> cuckooInsertReceiver(
    const std::vector<std::vector<int64_t>>& Y,
    uint32_t m,   // number of bins
    uint32_t h    // number of hash functions
) {
    std::vector<BinEntry> bins(m, BinEntry());

    for (auto& y : Y) {
        bool ok = false;
        for (uint32_t i = 0; i < h; i++) {
            if (Insert(bins, y, i, m, h)) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            std::cerr << "Insertion failed for " << y << std::endl;
            throw std::runtime_error("Cuckoo hashing failed");
        }
    }
    return bins;
}

std::vector<int64_t> computeCuckooHashTableClient(
    std::vector<std::vector<int64_t>> &inputVec,
    uint32_t ringDim,
    int64_t dummyVal
) {
    uint32_t dimElem = inputVec[0].size();
    uint32_t numBins = ringDim / dimElem;

    std::vector<BinEntry> hashBins = cuckooInsertReceiver(
        inputVec, numBins, 3
    );

    // Interpret Bins
    std::vector<int64_t> ret(ringDim, dummyVal);
 
    for (uint32_t i = 0; i < numBins; i++) {
        auto currBin = hashBins[i];
        if (currBin.isEmpty) {
            continue;
        } else {
            for (uint32_t j = 0; j < dimElem; j++) {
                ret[i + numBins * j] = currBin.value[j];
            }
        }
    }
    return ret;
}

std::vector<std::vector<int64_t>> computeCuckooHashTableServer(
    std::vector<std::vector<int64_t>> inputVec,
    uint32_t ringDim,
    uint32_t maxBin,
    int64_t dummyVal,
    uint32_t h
) {
    // Assume that the input vector is already pre-processed well.
    uint32_t dimElem = inputVec[0].size();
    uint32_t numBins = ringDim / dimElem;
    std::vector<std::vector<int64_t>> retTable(ringDim);
    std::vector<uint32_t> currItems(ringDim, 0);

    std::cout << "Max Bin: " << maxBin << std::endl;    


    for (auto& innerVec: retTable) {
        innerVec.resize(maxBin, dummyVal);
    }        

    for (uint32_t i = 0; i < inputVec.size(); i++) {

        for (uint32_t j = 0; j < h; j++) {
            uint64_t ret = computeHash(inputVec[i], j) % numBins;

            // Place values with Jumps!
            for (uint32_t k = 0; k < dimElem; k++) {
                uint32_t currIdx = ret + numBins * k;
                
                retTable[currIdx][currItems[currIdx]] = inputVec[i][k];
                currItems[currIdx]++;
                if (currItems[currIdx] > maxBin) {
                    throw std::runtime_error("Too many items in a bin");
                }
            }
        }
    }

    uint32_t actualMaxBin = *std::max_element(currItems.begin(), currItems.end());

    // Trim the table
    for (auto& innerVec: retTable) {
        innerVec.resize(maxBin);
    }        

    std::cout << "Actual Max Bin: " << actualMaxBin << std::endl;
    return retTable;
}