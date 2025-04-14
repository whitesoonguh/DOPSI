#include "APSI_tests.h"

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
    uint32_t itemLen,
    uint32_t prime
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(3, ((int64_t)1 << 16) - 1);

    std::vector<std::vector<int64_t>> ret(numItem);
    #pragma omp parallel for
    for (uint32_t i = 0; i < numItem; i++) {
        std::vector<int64_t> _tmp(itemLen);
        for (uint32_t j = 0; j < itemLen; j++) {
            _tmp[j] = (dist(gen) % prime);
        }
        ret[i] = _tmp;
    }
    return ret;
}

void testFullProtocol(uint32_t numParties, uint32_t numItem, bool isEncrypted) {
    uint32_t actualNumItem = 1<<numItem;
    uint32_t itemLen = 5;
    uint32_t prime = (1<<16) + 1;
    uint32_t remDepth = std::ceil(std::log2(numParties));
    HE bfv("BFV", 65537, isEncrypted + remDepth);    

    std::cout << remDepth << std::endl;

    std::cout << "Generate Random Data..." << std::endl;
    auto msgVec = genData(actualNumItem, itemLen, prime);
    std::cout << "Done!" << std::endl;

    // Dummy Value..?
    // Just wanted to avoid errors when generating tables.
    uint32_t maxBin;
    if (numItem <= 20) {
        maxBin = 1000;    
    } else {
        maxBin = 1000 * (1<< (numItem - 20));
    }
    
    std::cout << maxBin << std::endl;

    std::cout << "Create Hash Table..." << std::endl;
    auto hashTable = computeHashTable(
        msgVec, bfv.ringDim, maxBin, -1
    );
    std::cout << "Done!" << std::endl;    

    // Create Query Value
    uint32_t numPowers = 55;
    std::vector<uint32_t> pos(numPowers);
    for (uint32_t i = 0; i < numPowers; i++) {
        pos[i] = i + 1;
    }
    NTTContext ctx(bfv.prime, 3, 1<<16);
    APSIParams params {
        pos, 5, numPowers, 0
    };    



    std::vector<int64_t> queryMsg = msgVec[0];
    std::cout << "Construct Query" << std::endl;
    APSIQuery query = constructQuery(
        bfv, params, queryMsg
    );
    size_t ctSize = ctxtSize(query.powers[0]);
    size_t querySize = ctxtSize(query.powers[0]) * query.powers.size();
    std::cout << "Done!" << std::endl;
    std::cout << "Ctxt Size: " << (double)ctSize / 1000000 << "MB" << std::endl;    
    std::cout << "Query Size: " << (double)querySize / 1000000 << "MB" << std::endl;    

    std::vector<Ciphertext<DCRTPoly>> retCtxts;

    if (isEncrypted) {
        std::cout << "Construct Database" << std::endl;    
        APSICtxtDB DB = constructCtxtDB(bfv, ctx, hashTable, numPowers);
        std::cout << "Done!" << std::endl;    

        std::cout << "Compute Intersection" << std::endl;
        auto t1 = std::chrono::high_resolution_clock::now();
        retCtxts = compInterCtxt(
            bfv, params, DB, query, remDepth
        );
        auto t2 = std::chrono::high_resolution_clock::now();
        auto tdiff = std::chrono::duration<double>(t2-t1).count();    
        std::cout << "Done!" << std::endl;
        std::cout << "Inter Time: " << tdiff << std::endl;    

        size_t responseSize = ctxtSize(retCtxts[0]) * retCtxts.size();
        std::cout << "Response Size: " << (double)(responseSize) / 1000000 << "MB" << std::endl;        
    } else {
        std::cout << "Construct Database" << std::endl;    
        NTTContext ctx(bfv.prime, 3, 1<<16);
        APSIPtxtDB DB = constructPtxtDB(bfv, ctx, hashTable, numPowers);
        std::cout << "Done!" << std::endl;            


        std::cout << "Compute Intersection for PtxtDB" << std::endl;
        auto t1 = std::chrono::high_resolution_clock::now();
        retCtxts = compInterPtxt(
            bfv, params, DB, query, remDepth
        );
        auto t2 = std::chrono::high_resolution_clock::now();
        auto tdiff = std::chrono::duration<double>(t2-t1).count();    
        std::cout << "Done!" << std::endl;
        std::cout << "Inter Time: " << tdiff << std::endl;            
        size_t responseSize = ctxtSize(retCtxts[0]) * retCtxts.size();
        std::cout << "Response Size: " << (double)(responseSize) / 1000000 << "MB" << std::endl;                
    }

    // Do Aggergation
    // Make Dummy Ctxts
    std::vector<std::vector<Ciphertext<DCRTPoly>>> responses(numParties);
    responses[0] = retCtxts;
    for (uint32_t i = 1; i < numParties; i++) {
        std::vector<Ciphertext<DCRTPoly>> _tmp(retCtxts.begin(), retCtxts.end());
        responses[i] = _tmp;
    }
    // Do Aggregation!
    std::cout << "Aggregation Start..." << std::endl;
    auto t1 = std::chrono::high_resolution_clock::now();
    auto retCtxt = compAggResponse(bfv, responses);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto tdiff = std::chrono::duration<double>(t2-t1).count();    
    std::cout << "Done!" << std::endl;
    std::cout << "Aggregation Time: " << tdiff << std::endl;
    std::cout << "Aggregated Size: " << (double)ctxtSize(retCtxt[0]) * retCtxt.size() / 1000000 << "MB" << std::endl;
}



void testFullProtocolTwoParty(int numParties) {
    uint32_t numItem = 1<<20;
    uint32_t itemLen = 5;
    uint32_t prime = (1<<16) + 1;
    HE bfv("BFV", 65537, 0 + std::ceil(std::log2(numParties)));
    
    std::cout << "Generate Random Data..." << std::endl;
    auto msgVec = genData(numItem, itemLen, prime);
    std::cout << "Done!" << std::endl;

    // Dummy Value..?
    uint32_t maxBin = 1000;

    // Create a hash table
    std::cout << "Create Hash Table..." << std::endl;
    auto hashTable = computeHashTable(
        msgVec, bfv.ringDim, maxBin, -1
    );
    std::cout << "Done!" << std::endl;    

    // Construct DB
    std::cout << "Construct Database" << std::endl;    
    NTTContext ctx(bfv.prime, 3, 1<<16);
    APSIPtxtDB DB = constructPtxtDB(bfv, ctx, hashTable, 55);
    std::cout << "Done!" << std::endl;    

    // Create Query Value
    std::vector<uint32_t> pos(55);
    for (uint32_t i = 0; i < 55; i++) {
        pos[i] = i + 1;
    }

    APSIParams params {
        pos, 5, 55, 0
    };

    std::vector<int64_t> queryMsg = msgVec[0];    
    std::cout << "Construct Query" << std::endl;
    APSIQuery query = constructQuery(
        bfv, params, queryMsg
    );
    size_t querySize = ctxtSize(query.powers[0]) * query.powers.size();
    std::cout << "Done!" << std::endl;
    std::cout << "Query Size: " << (double)querySize / 1000000 << "MB" << std::endl;

    // Do Intersection
    std::cout << "Compute Intersection" << std::endl;
    auto t1 = std::chrono::high_resolution_clock::now();
    auto retCtxts = compInterPtxt(
        bfv, params, DB, query, 0
    );
    auto t2 = std::chrono::high_resolution_clock::now();
    auto tdiff = std::chrono::duration<double>(t2-t1).count();    
    std::cout << "Done!" << std::endl;
    std::cout << "Time Elapsed: " << tdiff << std::endl;    

    size_t responseSize = ctxtSize(retCtxts[0]) * retCtxts.size();
    std::cout << "Response Size: " << (double)(responseSize) / 1000000 << "MB" << std::endl;

    // Decryption
    auto retRes = findIntersection(bfv, params, retCtxts);

    if (!get<0>(retRes)) {
        std::cout << "Intersection Not Found..." << std::endl;
    } else {
        std::cout << "Intersection Found!" << std::endl;
        std::vector<int64_t> retMsg = bfv.decrypt(retCtxts[get<2>(retRes)])->GetPackedValue();
        std::cout << std::vector<int64_t>(
            retMsg.begin() + params.itemLen * get<1>(retRes),
            retMsg.begin() + params.itemLen * (get<1>(retRes) + 1)
        ) << std::endl;
    }
    

}


void testSender() {
    uint32_t numItem = 1<<24;
    uint32_t itemLen = 5;
    uint32_t prime = (1<<16) + 1;
    HE bfv("BFV", 65537, 3);

    std::cout << "Generate Random Data..." << std::endl;
    auto msgVec = genData(numItem, itemLen, prime);
    std::cout << "Done!" << std::endl;

    // Dummy Value..?
    uint32_t maxBin = 10000;

    // Create a hash table
    std::cout << "Create Hash Table..." << std::endl;
    auto hashTable = computeHashTable(
        msgVec, bfv.ringDim, maxBin, -1
    );
    std::cout << "Done!" << std::endl;    

    // Construct DB
    std::cout << "Construct Database" << std::endl;    
    NTTContext ctx(bfv.prime, 3, 1<<16);
    APSIPtxtDB DB = constructPtxtDB(bfv, ctx, hashTable, 65);
    std::cout << "Done!" << std::endl;    

}

void testHashing() {
    // Parameters
    uint32_t numItem = 1<<20;
    uint32_t itemLen = 5;
    uint32_t prime = (1<<16) + 1;
    uint32_t ringDim = 1<<14;

    std::cout << "Generate Random Data..." << std::endl;
    auto msgVec = genData(numItem, itemLen, prime);
    std::cout << "Done!" << std::endl;

    // Dummy Value..?
    uint32_t maxBin = 1000;

    // Create a hash table
    std::cout << "Create Hash Table..." << std::endl;
    auto hashTable = computeHashTable(
        msgVec, ringDim, maxBin, -1
    );

    std::cout << "Done!" << std::endl;
}


void testPolyOps() {
    {   
        std::cout << "<<< NTT TEST >>>" << std::endl;
        int64_t prime = 65537;
        NTTContext ctx(prime, 3, 1<<16);
        std::vector<int64_t> fa = {2,2, 1};
        std::vector<int64_t> fb = {1,3,3, 1};
    
        auto ret1 = PolyMulTextBook(fa, fb, prime);
        auto ret2 = PolyMultNTT(ctx, fa, fb);
    
        std::cout << std::vector<int64_t>(ret1.begin(), ret1.end()) << std::endl;
        std::cout << std::vector<int64_t>(ret2.begin(), ret2.end()) << std::endl;        
    }

    {
        std::cout << "<<< Interpolation TEST >>>" << std::endl;
        int64_t prime = 65537;
        NTTContext ctx(prime, 3, 1<<16);        
        std::vector<int64_t> vals = {
            1,2,3,4,
            5,6,7,8,
            9,10,11,12,
            13,14,15,16
        };

        auto ret1 = constructInterPolyNaive(vals, prime);
        auto ret2 = constructInterPoly(ctx, vals);

        std::cout << std::vector<int64_t>(ret1.begin(), ret1.end()) << std::endl;
        std::cout << std::vector<int64_t>(ret2.begin(), ret2.end()) << std::endl;                


        // Stress Test
        std::vector<int64_t> vals2(1<<16);
        for (uint32_t i = 0; i < 1<<16; i++) {
            vals2[i] = i+1;
        }

        // Naive
        std::cout << "Stress Test Start!" << std::endl;
        auto t1_1 = std::chrono::high_resolution_clock::now();
        ret1 = constructInterPolyNaive(vals2, prime);
        auto t2_1 = std::chrono::high_resolution_clock::now();
        auto tdiff_1 = std::chrono::duration<double>(t2_1 - t1_1).count();
        std::cout << "Naive: " << tdiff_1 << std::endl;

        auto t1_2 = std::chrono::high_resolution_clock::now();
        ret2 = constructInterPoly(ctx, vals2);
        auto t2_2 = std::chrono::high_resolution_clock::now();
        auto tdiff_2 = std::chrono::duration<double>(t2_2 - t1_2).count();
        std::cout << "improved: " << tdiff_2 << std::endl;        

        auto evRet1 = PolyEval(ret1, 3, 65537);
        auto evRet2 = PolyEval(ret2, 3, 65537);

        std::cout << "First Eval Result: " << evRet1 << std::endl;
        std::cout << "Second Eval Result: " << evRet2 << std::endl;
    }
}

void testPolyEvals() {
    HE bfv("BFV", 65537, 3);
    {
        std::cout << "TEST on PolyEvalLinear" << std::endl;
        int64_t x = 5;
        uint32_t degree = 12;
        std::vector<Ciphertext<DCRTPoly>> powers(degree);
        for (uint32_t i = 0; i < degree; i++) {
            int64_t currVal = modPow(x, i+1, 65537);
            std::vector<int64_t> _tmp(bfv.ringDim, currVal);
            Plaintext _ptxt = bfv.packing(_tmp);
            powers[i] = bfv.encrypt(_ptxt);
            // std::cout << "[DEBUG] Current Power: 5^i = " << currVal << std::endl;
        }
        std::vector<Plaintext> coeffs(degree + 1);
        std::vector<int64_t> rawCoeffs(degree + 1);
        for (uint32_t i = 0; i < degree + 1; i++) {
            rawCoeffs[i] = (i+42) % 65537;
        }

        for (uint32_t i=0; i<degree+1; i++) {
            std::vector<int64_t> _tmp(bfv.ringDim, rawCoeffs[i]);
            coeffs[i] = bfv.packing(_tmp);
        }
        auto ret = PolyEvalLinearPtxt(bfv, coeffs, powers);

        std::vector<int64_t> retMsg = bfv.decrypt(ret)->GetPackedValue();
        std::cout << "Output: " << std::endl;
        std::cout << std::vector<int64_t>(retMsg.begin(), retMsg.begin() + 10) << std::endl;
        int64_t outFromRaw = rawCoeffs[0];
        for (uint i = 0; i < degree; i++) {
            outFromRaw = (outFromRaw + rawCoeffs[i+1] * modPow(5, i+1, 65537) ) % 65537;
        }
        std::cout << "Output from Raw Data: " << outFromRaw << std::endl;
    }

    {
        std::cout << "TEST on PolyEvalPS" << std::endl;
        int64_t x = 5;
        uint32_t degree = 12;
        std::vector<Ciphertext<DCRTPoly>> powers(degree);
        for (uint32_t i = 0; i < degree; i++) {
            int64_t currVal = modPow(x, i+1, 65537);
            std::vector<int64_t> _tmp(bfv.ringDim, currVal);
            Plaintext _ptxt = bfv.packing(_tmp);
            powers[i] = bfv.encrypt(_ptxt);
            // std::cout << "[DEBUG] Current Power: 5^i = " << currVal << std::endl;
        }
        std::vector<Plaintext> coeffs(degree + 1);
        std::vector<int64_t> rawCoeffs(degree + 1);
        for (uint32_t i = 0; i < degree + 1; i++) {
            rawCoeffs[i] = (i+42) % 65537;
        }

        for (uint32_t i=0; i<degree+1; i++) {
            std::vector<int64_t> _tmp(bfv.ringDim, rawCoeffs[i]);
            coeffs[i] = bfv.packing(_tmp);
        }
        auto ret = PolyEvalPS(bfv, coeffs, powers, 3);

        std::vector<int64_t> retMsg = bfv.decrypt(ret)->GetPackedValue();
        std::cout << "Output: " << std::endl;
        std::cout << std::vector<int64_t>(retMsg.begin(), retMsg.begin() + 10) << std::endl;
        int64_t outFromRaw = rawCoeffs[0];
        for (uint i = 0; i < degree; i++) {
            outFromRaw = (outFromRaw + rawCoeffs[i+1] * modPow(5, i+1, 65537) ) % 65537;
        }
        std::cout << "Output from Raw Data: " << outFromRaw << std::endl;
    }
}

void testIntersectionPoly() {
    HE bfv("BFV", 65537, 3);
    NTTContext ctx(65537, 3, 1<<16);
    {
        std::cout << "TEST INTERSECTION POLY" << std::endl;
        uint32_t numItems = 32;
        std::vector<int64_t> rawData(numItems);
        for (uint32_t i = 0; i < numItems; i++) {
            rawData[i] = i + 1;
        }
        std::vector<int64_t> memPoly = constructInterPoly(ctx, rawData);
        int64_t query = 2;

        // Construct Powers
        std::vector<int64_t> rawPowers(numItems); 
        for (uint32_t i = 0; i < numItems; i++) {
            rawPowers[i] = modPow(query, i+1, 65537);
        }

        // Construct Query ctxts
        std::vector<Ciphertext<DCRTPoly>> powers(numItems);
        for (uint32_t i = 0; i < numItems; i++) {
            std::vector<int64_t> _tmpMsg(bfv.ringDim, rawPowers[i]);
            Plaintext _tmp = bfv.packing(_tmpMsg);
            powers[i] = bfv.encrypt(_tmp);
        }

        // Construct Coeffs
        std::vector<Plaintext> coeffs(numItems + 1);
        for (uint32_t i = 0; i < numItems + 1; i++) {
            std::vector<int64_t> _tmpMsg(bfv.ringDim, memPoly[i]);
            coeffs[i] = bfv.packing(_tmpMsg);
        }
        auto ret = PolyEvalLinearPtxt(bfv, coeffs, powers);


        std::vector<int64_t> retMsg = bfv.decrypt(ret)->GetPackedValue();
        std::cout << "Output: " << std::endl;
        std::cout << std::vector<int64_t>(retMsg.begin(), retMsg.begin() + 10) << std::endl;
        int64_t outFromRaw = memPoly[0];
        for (uint i = 0; i < numItems; i++) {
            outFromRaw = (outFromRaw + memPoly[i+1] * modPow(query, i+1, 65537) ) % 65537;
        }
        std::cout << "Output from Raw Data: " << outFromRaw << std::endl;        
    }
}