#include "APSI_tests.h"
#include <iostream>
#include <cstdlib>  // for std::atoi
#include <string>
#include <map>

// Helper function to check if a string is a valid positive integer
bool isValidNumber(const std::string& str) {
    if (str.empty()) return false;
    for (char c : str) {
        if (!std::isdigit(c)) return false;
    }
    return true;
}

// Function to print usage instructions
void printUsage() {
    std::cerr << "\nUsage: ./main_apsi"
              << " -numParties <int>"
              << " -numItems <int>"
              << " -isEncrypted <bool>"
              << " -isPSI <bool>" << "\n\n";
            //   << " -allowIntersection <0 or 1>\n\n"
            //   << "Example:\n"
            //   << "  ./main -numItem 30 -lenData 2 -numPack 4 -numAgg 10 -alpha 5 -interType (CI or CPI or CIH or CPIH) -allowIntersection 1 \n\n";
}

int main(int argc, char* argv[]) {
    // We want ALL flags to be supplied. List them here:
    const std::string REQUIRED_FLAGS[] = {
        "-numParties",  "-isEncrypted", "-numItems", "-isPSI"
    };

    // Store all key-value pairs in a map
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc - 1; i += 2) {
        std::string key = argv[i];
        std::string value = argv[i + 1];

        // Check for flags that start with "-"
        if (key.size() > 1 && key[0] == '-') {
            args[key] = value;
        } else {
            std::cerr << "Error: Invalid flag '" << key << "'.\n";
            printUsage();
            return 1;
        }
    }

    // 1. Check if all required flags are present
    for (const auto& flag : REQUIRED_FLAGS) {
        if (args.find(flag) == args.end()) {
            std::cerr << "Error: Missing required flag '" << flag << "'.\n";
            printUsage();
            return 1;
        }
    }

    // 2. Now parse and validate each argument
    //    (We know they exist, but we must ensure they are valid.)

    // Parse numItem
    if (!isValidNumber(args["-numParties"])) {
        std::cerr << "Error: numParties must be a positive integer.\n";
        return 1;
    }
    int numParties = std::atoi(args["-numParties"].c_str());

    if (!isValidNumber(args["-numItems"])) {
        std::cerr << "Error: numItems must be a positive integer.\n";
        return 1;
    }
    int numItems = std::atoi(args["-numItems"].c_str());


    // parse isencrypted
    if (args["-isEncrypted"] != "0" && args["-isEncrypted"] != "1") {
        std::cerr << "Error: isEncrypted must be either 0 (false) or 1 (true).\n";
        return 1;
    }
    bool isEncrypted = (args["-isEncrypted"] == "1");

    if (args["-isPSI"] != "0" && args["-isPSI"] != "1") {
        std::cerr << "Error: isPSI must be either 0 (false) or 1 (true).\n";
        return 1;
    }
    bool isPSI = (args["-isPSI"] == "1");    

    // 3. Print final values
    std::cout << "Running testFullProtocol with:\n"
              << "  numParties     = " << numParties << "\n"
              << "  numItems     = " << numItems << "\n"
              << "  isEncrypted = " << isEncrypted << "\n"
              << "  isPSI = " << isPSI << "\n"
              << "\n";

    if (isPSI) {
        testFullPSI(
            numParties, numItems, isEncrypted
        );
    } else {
        testFullProtocol(
            numParties, numItems, isEncrypted
        );
    }
    return 0;
}


// int main() {
//     // testHashing();
//     // testPolyOps();
//     // testSender();
//     testFullProtocolTwoParty();
//     // testPolyEvals();
//     // testIntersectionPoly();
//     return 0;
// }