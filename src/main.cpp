#include <iostream>
#include <cstdlib>  // for std::atoi
#include <string>
#include <map>
#include <tests.h>

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
    std::cerr << "\nUsage: ./main"
              << " -numItem <int>"
              << " -lenData <int>"
              << " -numPack <int>"
              << " -numAgg <int>"
              << " -alpha <int>"
              << " -interType <string>"
              << " -allowIntersection <0 or 1>\n\n"
              << "Example:\n"
              << "  ./main -numItem 30 -lenData 2 -numPack 4 -numAgg 10 -alpha 5 -interType (CI or CPI or CIH or CPIH) -allowIntersection 1 \n\n";
}

int main(int argc, char* argv[]) {
    // We want ALL flags to be supplied. List them here:
    const std::string REQUIRED_FLAGS[] = {
        "-numItem", "-lenData", "-numPack", "-numAgg", "-alpha", "-interType", "-allowIntersection"
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
    if (!isValidNumber(args["-numItem"])) {
        std::cerr << "Error: numItem must be a positive integer.\n";
        return 1;
    }
    int numItem = std::atoi(args["-numItem"].c_str());

    // Parse lenData
    if (!isValidNumber(args["-lenData"])) {
        std::cerr << "Error: lenData must be a positive integer.\n";
        return 1;
    }
    int lenData = std::atoi(args["-lenData"].c_str());

    // Parse numPack
    if (!isValidNumber(args["-numPack"])) {
        std::cerr << "Error: numPack must be a positive integer.\n";
        return 1;
    }
    int numPack = std::atoi(args["-numPack"].c_str());

    // Parse numAgg
    if (!isValidNumber(args["-numAgg"])) {
        std::cerr << "Error: numAgg must be a positive integer.\n";
        return 1;
    }
    int numAgg = std::atoi(args["-numAgg"].c_str());

    // Parse alpha
    if (!isValidNumber(args["-alpha"])) {
        std::cerr << "Error: alpha must be a positive integer.\n";
        return 1;
    }
    int alpha = std::atoi(args["-alpha"].c_str());

    // Parse interType
    std::string interType = args["-interType"];
    if (interType.empty()) {
        std::cerr << "Error: interType must be a non-empty string.\n";
        return 1;
    }

    // Parse allowIntersection (should be 0 or 1)
    if (args["-allowIntersection"] != "0" && args["-allowIntersection"] != "1") {
        std::cerr << "Error: allowIntersection must be either 0 (false) or 1 (true).\n";
        return 1;
    }
    bool allowIntersection = (args["-allowIntersection"] == "1");

    // 3. Print final values
    std::cout << "Running testFullProtocol with:\n"
              << "  numItem   = " << numItem << "\n"
              << "  lenData   = " << lenData << "\n"
              << "  numPack   = " << numPack << "\n"
              << "  numAgg    = " << numAgg << "\n"
              << "  alpha     = " << alpha << "\n"
              << "  interType = " << interType << "\n"
              << "  allowIntersection = " << (allowIntersection ? "true" : "false") << "\n";

    // testAllBackends();
    // testBasicOPs();
    // testProbNPC(512);
    // testRotAgg(1024);
    // testSanityCheck(32);
    // testVAFandAggCheck(1024);

    // Main Function for Measuring Aggregation Time
    // testAggCheck(1024);

    // Main Protocol for the Single Server
    testFullProtocol(numItem, lenData, numPack, numAgg, alpha, interType, allowIntersection);

    return 0;
}
