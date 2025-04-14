#ifndef HE_H
#define HE_H

#include <openfhe.h>

using namespace lbcrypto;

class HE {
public:
    int64_t ringDim;
    int64_t prime;    

    // Constructor for BFV or BGV mode, but default here is BFV.
    HE(const std::string& mode    = "BFV",
       int64_t          modulus = 65537,
       int32_t          depth   = 20
    ) 
    {
        // Note: SetThresholdNumOfParties = 1 (Default Parameter) is equivalent to Trusted Setup.
        // https://github.com/openfheorg/openfhe-development/blob/6bcca756e9d52b4db3dd2168414df8a7316b1a61/src/pke/lib/scheme/bfvrns/bfvrns-leveledshe.cpp
        // https://eprint.iacr.org/2020/304.pdf
        
        if (mode == "BFV") {
            CCParams<CryptoContextBFVRNS> parameters;
            parameters.SetPlaintextModulus(modulus);
            parameters.SetMultiplicativeDepth(depth);
            // This is for the noise flooding; 128-bit noise is added to the final ciphertext.
            parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
            std::cout  << "Parameters: " << parameters << std::endl;
            std::cout << CryptoContextBFVRNS::CryptoParams::EstimateMultipartyFloodingLogQ() << std::endl;            
            cc = GenCryptoContext(parameters);
        } else if (mode == "BGV") {
            CCParams<CryptoContextBGVRNS> parameters;
            parameters.SetPlaintextModulus(modulus);
            parameters.SetMultiplicativeDepth(depth);
            parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
            std::cout  << "Parameters: " << parameters << std::endl;
            cc = GenCryptoContext(parameters);
        } else {
            throw std::runtime_error("Invalid scheme mode: " + mode);
        }

        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(MULTIPARTY);

        keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        cc->EvalRotateKeyGen(keyPair.secretKey, {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768});


        // Print some approximate stats (optional)
        // Note: in BFV/BGV, GetPlaintextModulus() is not the same as ciphertext modulus,
        // but we replicate the Python code's approximate logging.
        double logPtMod = std::log2(cc->GetCryptoParameters()->GetPlaintextModulus());
        double logRing  = std::log2(cc->GetRingDimension());
        // double sizeMB   = (double)cc->GetRingDimension() 
        //                 * log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
        //                 * 2.0 / 8.0 / 1000000.0;

        // BFV parameter
        ringDim = cc->GetRingDimension();
        prime = modulus;

        std::cout << "Mode: " << mode << std::endl;
        std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
        std::cout << "Plaintext Modulus, p (bit) approx: " << logPtMod << std::endl;
        std::cout << "Ring Dimension, N (log) approx:    " << logRing << std::endl;
        // std::cout << "CTXT Size in MB approx:         " << sizeMB << std::endl;
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

    Ciphertext<DCRTPoly> add(const Plaintext& a,
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

    Ciphertext<DCRTPoly> addmany(
        const std::vector<Ciphertext<DCRTPoly>> &ct
    ) {
        return cc->EvalAddMany(ct);
    }    

    Ciphertext<DCRTPoly> multmany(
        const std::vector<Ciphertext<DCRTPoly>> &ct
    ) {
        return cc->EvalMultMany(ct);
    }    

    Ciphertext<DCRTPoly> compress(
        const Ciphertext<DCRTPoly> &ct,
        uint32_t level=0
    ) {
        return cc->Compress(ct, level);
    }

    // (Optional) Rescale or compress if needed – not shown here
    // ...

private:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;;
};

#endif