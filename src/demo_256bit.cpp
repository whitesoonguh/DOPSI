#include <openfhe.h>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>
#include "demo_256bit.h"

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

    // (Optional) Rescale or compress if needed – not shown here
    // ...

private:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;;
};

//-----------------------------------------
// merge(...) and zeromap_compose(...)
//-----------------------------------------

/**
 * merge(bfv, diff1, diff2, pt3):
 *   diff1 = diff1^2
 *   diff2 = diff2^2
 *   diff2_sq * pt3
 *   return diff1_sq - diff23
 */
Ciphertext<DCRTPoly> merge(HE& bfv,
                           Ciphertext<DCRTPoly> diff1,
                           Ciphertext<DCRTPoly> diff2,
                           Plaintext pt3)
{
    auto diff1_sq = bfv.square(diff1);
    auto diff2_sq = bfv.square(diff2);
    auto diff2_mul_pt3 = bfv.mult(diff2_sq, pt3);
    auto result = bfv.sub(diff1_sq, diff2_mul_pt3);
    return result;
}

/**
 * zeromap_compose(bfv, ctxts, pt3):
 *   if size == 1 => return ctxts[0]
 *   if size == 2 => merge(ctxts[0], ctxts[1], pt3)
 *   else => recursively compose
 */
Ciphertext<DCRTPoly> zeromap_compose(
    HE& bfv,
    const std::vector<Ciphertext<DCRTPoly>>& ctxts,
    Plaintext pt3)
{
    if (ctxts.size() == 1) {
        return ctxts[0];
    } else if (ctxts.size() == 2) {
        return merge(bfv, ctxts[0], ctxts[1], pt3);
    } else {
        size_t mid = ctxts.size() / 2;
        std::vector<Ciphertext<DCRTPoly>> left(ctxts.begin(), ctxts.begin() + mid);
        std::vector<Ciphertext<DCRTPoly>> right(ctxts.begin() + mid, ctxts.end());

        auto ret1 = zeromap_compose(bfv, left, pt3);
        auto ret2 = zeromap_compose(bfv, right, pt3);

        std::vector<Ciphertext<DCRTPoly>> mergedTwo {ret1, ret2};
        return zeromap_compose(bfv, mergedTwo, pt3);
    }
}

/*
Optimized zeromap_compose
This avoids function-level recursion.
*/
Ciphertext<DCRTPoly> zeromap_compose_v2(
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

        // Update index
        nctxts>>=1;
    }
    return ctxts[0];
}

//-----------------------------------------
// Replicate the Python logic in a single function
//-----------------------------------------

void runDemo() {
    // Equivalent to: bfv = HE(mode="BFV", modulus=65537, depth=20)
    HE bfv("BFV", 65537, 21);

    // y = encode_val(42, 1<<15)
    auto yvec   = encode_val(42, 1ULL << 15);
    auto ctxt_y = bfv.encrypt( bfv.packing(yvec) );

    double query_size = ctxt_size(ctxt_y);
    std::cout << "Size of query ctxt (MB): " << query_size/1000000 << std::endl;

    // pt3 = bfv.packing(encode_val(3, 1<<15))
    auto pt3 = bfv.packing( encode_val(3, 1ULL << 15) );

    // one = bfv.packing(np.ones(1<<15))
    std::vector<int64_t> ones(1ULL << 15, 1);
    auto ptOne = bfv.packing(ones);

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

    // diffs = [ctxt_y - ctxt_x for ctxt_x in ctxts]
    std::vector<Ciphertext<DCRTPoly>> diffs;
    for (auto &ctxt_x : ctxts) {
        diffs.push_back( bfv.sub(ctxt_y, ctxt_x) );
    }

    // ret = zeromap_compose(bfv, diffs, pt3)
    auto ret = zeromap_compose_v2(bfv, diffs, pt3);

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
}

