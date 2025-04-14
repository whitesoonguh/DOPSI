#include <openfhe.h>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>
#include "demo_comp.h"

using namespace lbcrypto;

//-----------------------------------------
// Helper Functions
//-----------------------------------------

// Compute size of a ciphertext in memory
using OFHECtxt = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

size_t ctxt_size(OFHECtxt& ctxt) {
  size_t size = 0;
  for (auto& element : ctxt->GetElements()) {
    for (auto& subelements : element.GetAllElements()) {
      auto lenght = subelements.GetLength();
      size += lenght * sizeof(subelements[0]);
    }
  }
  return size;
};

/**
 * Encode a single integer value y into a large vector of length `size`.
 * Mimics Python's encode_val(y, size = 1<<15).
 */
std::vector<int64_t> encode_val(int64_t y, size_t size = (1ULL << 15)) {
    std::vector<int64_t> result(size, y);
    return result;
}

/**
 * Generate a random vector of length `size` with values between 0 and 2^16 - 1.
 * Mimics Python's generate_x(size = 1<<15).
 */
std::vector<int64_t> generate_x(size_t size = (1ULL << 15)) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, (1 << 16) - 1);

    std::vector<int64_t> result(size);
    for (size_t i = 0; i < size; i++) {
        result[i] = dist(gen);
    }
    return result;
}

//-----------------------------------------
// HE Wrapper Class
//-----------------------------------------

class HE {
public:
    // Constructor for BFV or BGV mode, but default here is BFV.
    HE(const std::string& mode    = "BFV",
       uint64_t          modulus = 65537,
       uint32_t          depth   = 20) 
    {
        if (mode == "BFV") {
            CCParams<CryptoContextBFVRNS> parameters;
            parameters.SetPlaintextModulus(modulus);
            parameters.SetMultiplicativeDepth(depth);
            std::cout  << "Parameters: " << parameters << std::endl;
            cc = GenCryptoContext(parameters);
        } else if (mode == "BGV") {
            CCParams<CryptoContextBGVRNS> parameters;
            parameters.SetPlaintextModulus(modulus);
            parameters.SetMultiplicativeDepth(depth);
            std::cout  << "Parameters: " << parameters << std::endl;
            cc = GenCryptoContext(parameters);
        } else {
            throw std::runtime_error("Invalid scheme mode: " + mode);
        }

        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        cc->EvalRotateKeyGen(keyPair.secretKey, {1, 2, 4, 8});

        // Print some approximate stats (optional)
        // Note: in BFV/BGV, GetPlaintextModulus() is not the same as ciphertext modulus,
        // but we replicate the Python code's approximate logging.
        double logPtMod = std::log2(cc->GetCryptoParameters()->GetPlaintextModulus());
        double logRing  = std::log2(cc->GetRingDimension());
        double sizeMB   = (static_cast<double>(1ULL << static_cast<size_t>(std::round(logRing))) 
                         * logPtMod * 2.0) / (1ULL << 23);

        std::cout << "Mode: " << mode << std::endl;
        std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
        std::cout << "Plaintext Modulus, p (bit) approx: " << logPtMod << std::endl;
        std::cout << "Ring Dimension, N (log) approx:    " << logRing << std::endl;
        std::cout << "CTXT Size in MB approx:         " << sizeMB << std::endl;
    }

    // Packing/Encryption/Decryption
    Plaintext packing(const std::vector<int64_t>& vals) {
        return cc->MakePackedPlaintext(vals);
    }

    Ciphertext<DCRTPoly> encrypt(const Plaintext& pt) {
        return cc->Encrypt(keyPair.publicKey, pt);
    }

    Plaintext decrypt(const Ciphertext<DCRTPoly>& ct) {
        Plaintext result;
        cc->Decrypt(keyPair.secretKey, ct, &result);
        return result;
    }

    // Basic arithmetic
    Ciphertext<DCRTPoly> add(const Ciphertext<DCRTPoly>& a,
                             const Ciphertext<DCRTPoly>& b) {
        return cc->EvalAdd(a, b);
    }

    Ciphertext<DCRTPoly> sub(const Ciphertext<DCRTPoly>& a,
                             const Ciphertext<DCRTPoly>& b) {
        return cc->EvalSub(a, b);
    }

    Ciphertext<DCRTPoly> mult(const Ciphertext<DCRTPoly>& a,
                              const Ciphertext<DCRTPoly>& b) {
        return cc->EvalMult(a, b);
    }

    Ciphertext<DCRTPoly> mult(const Ciphertext<DCRTPoly>& a,
                              const Plaintext& b) {
        return cc->EvalMult(a, b);
    }

    Ciphertext<DCRTPoly> square(const Ciphertext<DCRTPoly>& x) {
        return cc->EvalSquare(x);
    }

    Ciphertext<DCRTPoly> sub(const Plaintext& pt, 
                             const Ciphertext<DCRTPoly>& ct) {
        return cc->EvalSub(pt, ct);
    }

    Ciphertext<DCRTPoly> rotate(const Ciphertext<DCRTPoly> &ct,
                                const int rotIdx) {
        return cc->EvalRotate(ct, rotIdx);
    }

    // (Optional) Rescale or compress if needed – not shown here
    // ...

private:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;;
};

//-----------------------------------------
// Tools for computing NPCs
//-----------------------------------------

// Optimized zeromap_compose. This avoids function-level recursion.
Ciphertext<DCRTPoly> zeromap_compose(
    HE& bfv,
    std::vector<Ciphertext<DCRTPoly>> &ctxts,
    Plaintext pt3) 
{
    int nctxts = ctxts.size();

    while (nctxts > 1) {
        // Square the ctxts
        for (int i = 0; i < nctxts; i++) {
            ctxts[i] = bfv.square(ctxts[i]);
        }

        // Multiply by 3
        for (int i = 0; i < nctxts; i += 2 ) {
            ctxts[i] = bfv.mult(ctxts[i], pt3);
        }

        // Merge by subtraction
        for (int i = 0; i < nctxts/2; i++) {
            ctxts[i] = bfv.sub(ctxts[2*i], ctxts[2*i + 1]);
        }

        // Update the # of valid ctxts
        nctxts>>=1;
    }
    return ctxts[0];
}

// Precomputing Function for Masking
std::vector<Plaintext> preprocessMasks(HE &bfv, int size, int k, int numMasks) {
    std::vector<Plaintext> ret; 

    // Number of Blocks
    int numBlocks = size / k;

    // Number of Ones in each block
    int numOfOne = k / numMasks;

    for (int i = 0; i < numMasks; i++) {
        std::vector<int64_t> tmp(size,0);

        // Put 1's for desired positions
        for (int j = 0; j < numBlocks; j++) {
            for (int l = 0; l < numOfOne; l++ ) {
                tmp[j * k + numOfOne * i + l] = 1;
            }
        };
        auto ptxt = bfv.packing(tmp);
        ret.push_back(ptxt);
    }
    return ret;
}

// Extract Ciphertexts via Rotation & Add
std::vector<Ciphertext<DCRTPoly>> extractCtxts(
    HE &bfv, 
    Ciphertext<DCRTPoly> ctxt,
    int k,
    const std::vector<Plaintext> &masks
)
{
    int numMasks = masks.size();
    std::vector<Ciphertext<DCRTPoly>> ret;
    Ciphertext<DCRTPoly> _tmp, __tmp;

    // Extraction goes here
    for (int i = 0; i < numMasks; i++) {
        // Multiply Mask
        _tmp = bfv.mult(ctxt, masks[i]);
        // Rotation and Add
        for (int j = 1; j < k; j *= 2) {
            __tmp = bfv.rotate(_tmp, j);
            _tmp = bfv.add(_tmp, __tmp);
        }
        ret.push_back(_tmp);
    }
    return ret;
}

//-----------------------------------------
// Utility Functions for Clients (Receiver)
//-----------------------------------------

// Prepare Msg of the Client
std::vector<int64_t> prepareMsg(
    std::vector<int64_t> &val,
    int64_t logp
) 
{
    int numVal = val.size();
    int numSegs = 64 / logp + (64 % logp != 0);

    // 11...1 (logp times)
    int64_t mask = (1<<logp) - 1;

    std::vector<int64_t> ret;

    for (int i = 0; i < numVal; i++) {
        int64_t currVal = val[i];
        for (int j = 0; j < numSegs; j++) {
            ret.push_back(currVal & mask);
            currVal >>= logp;
        }        
    }
    return ret;
}

// Duplicate and compose the message
// Without Compression
std::vector<Ciphertext<DCRTPoly>> prepareCtxtNoComp(
    HE &bfv,
    std::vector<int64_t> msg,
    int size
) {
    std::vector<Ciphertext<DCRTPoly>> ret;
    Plaintext packed;
    Ciphertext<DCRTPoly> ctxt;

    int numElts = msg.size();

    for (int i = 0; i < numElts; i++) {
        std::vector<int64_t> msgVec(size, msg[i]);
        packed = bfv.packing(msgVec);
        ctxt = bfv.encrypt(packed);
        ret.push_back(ctxt);
    }
    return ret;
}

// With Compression
Ciphertext<DCRTPoly> prepareCtxtComp(
    HE &bfv,
    std::vector<int64_t> msg,
    int size
) {
    int numElts = msg.size();
    std::vector<int64_t> msgVec;

    for (int i = 0; i < size; i++) {
        msgVec.push_back(msg[i % numElts]);
    }
    auto packed = bfv.packing(msgVec);
    auto ret = bfv.encrypt(packed);
    return ret;
}

//-----------------------------------------
// Utility functions for the server
//-----------------------------------------

// This encrypts the given database
// Not used in this demo.
std::vector<Ciphertext<DCRTPoly>> encryptDB(
    HE &bfv,
    std::vector<std::vector<int64_t>> &database,
    int64_t logp,
    int64_t size
) 
{
    // Computing the size
    int numData = database.size();
    int numElts = database[0].size() * (64 / logp + (64 % logp != 0));
    int numSegs = (numData / size + (numData % size != 0));

    // Here, # of ctxts becomes numSegs * numElts
    std::vector<Ciphertext<DCRTPoly>> ret;
    Plaintext _tmpPtxt;
    Ciphertext<DCRTPoly> _tmpCtxt;

    int bitmask = (1<<logp) - 1;

    // Runs over the "segments" of the database
    for (int i = 0; i < numSegs; i++) {
        int offset = i * size;

        // Runs over the data of each item
        for (int j = 0; j < numElts; j++) {
            std::vector<int64_t> _tmpMsgVec;
            int itemIdx = j / database[0].size();
            int maskIdx = j % database[0].size();

            // Runs over the items in the current segment
            for (int k = 0; k < size; k++) {
                int64_t currItem = (database[offset + k][itemIdx] >> (maskIdx * logp)) & bitmask;
                _tmpMsgVec.push_back(currItem);
            }

            // Do Encryption
            // TODO: Make a custom struct for handling each segment
            _tmpPtxt = bfv.packing(_tmpMsgVec);
            _tmpCtxt = bfv.encrypt(_tmpPtxt);
            ret.push_back(_tmpCtxt);
        }
    }
    return ret;
}


//-----------------------------------------
// Replicate the Python logic in a single function
//-----------------------------------------

// Encoding of four 42's in a single 64-bit integer.
#define theAnswer 0x002A002A002A002A

void runDemoComp() {

    // Equivalent to: bfv = HE(mode="BFV", modulus=65537, depth=20)
    HE bfv("BFV", 65537, 21);

    // y = encode_val(42, 1<<15)
    // Assume that ctxt_y is compressed
    std::vector<int64_t> clientMsg = {theAnswer, theAnswer, theAnswer, theAnswer};
    std::vector<int64_t> extenededMsg = prepareMsg(clientMsg, 16);
    auto ctxt_y = prepareCtxtComp(bfv, extenededMsg, 1ULL<<15);
    double query_size = ctxt_size(ctxt_y);
    std::cout << "Size of query ctxt (MB): " << query_size/1000000 << std::endl;

    // pt3 = bfv.packing(encode_val(3, 1<<15))
    auto pt3 = bfv.packing( encode_val(3, 1ULL << 15) );

    std::vector<int64_t> ones(1ULL << 15, 1);
    auto ptOne = bfv.packing(ones);

    // Precompute Masks 
    auto masks = preprocessMasks(bfv, 1ULL<<15, 16, 16);

    // Create 16 ciphertexts, each with the 28th element set to 42.
    std::vector<Ciphertext<DCRTPoly>> ctxts;
    for (int i = 0; i < (1 << 4); i++) {
        auto xvec = generate_x(1ULL << 15);
        xvec[27] = 42; // set index 27 to 42
        auto ctx = bfv.encrypt(bfv.packing(xvec));
        ctxts.push_back(ctx);
    }

    std::cout << "<<< START >>>" << std::endl;
    auto t1 = std::chrono::high_resolution_clock::now();

    // Unpack the ctxts
    auto ctxt_y_UP = extractCtxts(bfv, ctxt_y, 16, masks);

    // diffs = [ctxt_y - ctxt_x for ctxt_x in ctxts]
    std::vector<Ciphertext<DCRTPoly>> diffs;
    for (auto i = 0; i < 16; i++) {
        diffs.push_back( bfv.sub(ctxt_y_UP[i], ctxts[i]) );
    }

    // ret = zeromap_compose(bfv, diffs, pt3)
    auto ret = zeromap_compose(bfv, diffs, pt3);

    // for i in range(16): ret = bfv.square(ret)
    for (int i = 0; i < 16; i++) {
        ret = bfv.square(ret);
    }

    // ret_ctxt = bfv.sub(one, ret)
    // In Python, bfv.sub(ptOne, ret) => ptOne - ret
    auto ret_ctxt = bfv.sub(ptOne, ret);

    double sender_size = ctxt_size(ctxt_y);
    std::cout << "Size of sender ctxt (MB): " << sender_size/1000000 << std::endl;


    auto t2 = std::chrono::high_resolution_clock::now();
    double timeSec = std::chrono::duration<double>(t2 - t1).count();
    std::cout << "Time Elapsed: " << timeSec << "s" << std::endl;

    // ret = bfv.decrypt(ret_ctxt)
    auto ptRet = bfv.decrypt(ret_ctxt);
    auto& data = ptRet->GetPackedValue();

    // Print "Sanity Check: ret[27], sum(ret)"
    int64_t valAt27 = data[27];
    long long sumVal = 0;
    for (auto v : data) {
        sumVal += v;
    }
    std::cout << "Sanity Check: " << valAt27 << " " << sumVal << std::endl;

};