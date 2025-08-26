#include "test.h"

void testDOPMT(uint32_t logNumItem) {
    FHECTX ctx = initParams(65537, 18, 60);
    std::cout << "Prepare Data" << std::endl;
    std::vector<std::vector<int64_t>> serverData = genData(1<<logNumItem, 8, 1<<16);
    // std::vector<int64_t> clientData = genData(1, 8, 1<<16)[0];
    std::vector<int64_t> clientData(ctx.ringDim, 0);

    std::cout << "Prepare Query" << std::endl;
    Ciphertext<DCRTPoly> queryCtxt = queryCompress(ctx, clientData);

    std::cout << "Create Database" << std::endl;
    DOPMTDB serverDB = makeDOPMTDB(ctx, serverData, -3);

    std::cout << "Compute Intersection" << std::endl;
    auto t1 = std::chrono::high_resolution_clock::now();
    DOPMTServerResponse ret = compInterPMTServer(
        ctx, serverDB, queryCtxt, 1
    );
    auto t2 = std::chrono::high_resolution_clock::now();
    auto tdiff = std::chrono::duration<double>(t2-t1).count();

    std::cout << "Done!" << std::endl;
    std::cout << "Server Runtime: " << tdiff << "s" << std::endl;

    // Check output 
    Plaintext retPtxt;
    ctx.cc->Decrypt(ret.vafOutput, ctx.sk, &retPtxt);
    // std::cout << retPtxt->GetPackedValue() << std::endl;
}

void testDOPSI(uint32_t logNumItem) {
    FHECTX ctx = initParams(65537, 19, 60);
    std::cout << "Prepare Data" << std::endl;
    std::vector<std::vector<int64_t>> serverData = genData(1<<logNumItem, 8, 1<<16);
    std::vector<std::vector<int64_t>> clientData = genData(2048, 8, 1<<16);

    std::cout << "Prepare Query" << std::endl;
    Ciphertext<DCRTPoly> queryCtxt = queryCompressTable(ctx, clientData);

    std::cout << "Create Database" << std::endl;
    DOPMTDB serverDB = makeDOPSIDB(ctx, serverData, 3);

    
    std::cout << "Compute Intersection" << std::endl;
    auto t1 = std::chrono::high_resolution_clock::now();
    DOPMTServerResponse ret = compInterPSIServer(
        ctx, serverDB, queryCtxt, 1
    );
    auto t2 = std::chrono::high_resolution_clock::now();
    auto tdiff = std::chrono::duration<double>(t2-t1).count();

    std::cout << "Done!" << std::endl;
    std::cout << "Server Runtime: " << tdiff << "s" << std::endl;
}