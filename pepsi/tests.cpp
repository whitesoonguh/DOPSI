#include "pepsi_test.h"


// Helper for Simulation
std::vector<uint64_t> genDataPEPSI(
    int32_t numItem
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(3, ((uint64_t)1 << 16) - 1);

    std::vector<uint64_t> ret;
    for (int32_t i = 0; i < numItem; i++) {
        ret.push_back(dist(gen));
    }
    return ret;
}

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

double calcEltSize(
  uint32_t bitlen,
  uint32_t HW
) {
  double ret = 0;
  for (double i = 1; i <= HW; i++) {
    ret += std::log2(bitlen - i + 1) - std::log2(i);
  }
  return ret;
}


void testPEPSIProtocol(
  uint32_t numItem,
  uint32_t bitlen,
  uint32_t HW,
  bool isEncrypted
) {
    std::cout << "TEST START!" << std::endl;

    // Calucate Supporting Element Size
    double logEltSize = calcEltSize(bitlen, HW);
    std::cout << "Supporting Element Size (log2): " << logEltSize << std::endl;

    std::cout << "STEP 1-1: Setup FHE" << std::endl;
    HE bfv("BFV", 65537, (int)(std::log2(HW))+isEncrypted);

    std::cout << "Step 1-2: Setup Databases" << std::endl;
    std::vector<uint64_t> msgVec = genDataPEPSI(1<<numItem);

    std::cout << "Step 1-3: Server Side Preprocessing" << std::endl;
    PEPSIDB serverDB = constructPEPSIDB(
      bfv, msgVec, bitlen, HW, isEncrypted
    );


    std::cout << "Step 2: Client Side Computation" << std::endl;
    std::cout << "Step 3: Query Encryption" << std::endl;
    PEPSIQuery query = encryptClientData(bfv, 42, bitlen, HW);
    size_t querySize = ctxtSize(query.payload[0]) * query.numCtxt;

    std::cout << "Step 4: Do Intersection" << std::endl;
    ResponsePEPSIServer interResCtxt;

    auto t1 = std::chrono::high_resolution_clock::now();
    interResCtxt = compPEPSIInter(bfv, query, serverDB);
    auto t2 = std::chrono::high_resolution_clock::now();
    double timeSec = std::chrono::duration<double>(t2 - t1).count();
    std::cout << "Intersection Done! Time Elapsed: " << timeSec << "s" << std::endl;
    std::cout << "Step 5: Receive Result" << std::endl;
    auto ret = checkIntResult(bfv, interResCtxt.isInter);
    std::cout << "Inter Result: " << ret << std::endl;
    std::cout << "OpenFHE Query Size: " << (double)(querySize) / 1000000 << "MB" << std::endl;
}