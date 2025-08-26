#include "main.h"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <mode> <numItem>" << std::endl;
        return 1;
    }

    uint32_t mode = std::stoi(argv[1]);  
    uint32_t logNumItem = std::stoi(argv[2]);  
  
    if (mode == 1) {
        testDOPMT(logNumItem);
    } 
    else if (mode == 2) {
        testDOPSI(logNumItem);
    }
    
    return 0;
}