// src/scanner.cpp  (Phase 1 stub — replace fully in Phase 2)
#include "scanner.h"
#include <iostream>

Scanner::Scanner(const std::string& configPath) {
    entropyThreshold_ = 4.5;
    (void)configPath;
}

int Scanner::run(bool fullScan) {
    (void)fullScan;
    std::cout << "[GitSentry] Scanner not yet implemented.\n";
    return 0;
}

std::vector<DetectionResult> Scanner::scanDiff(const std::string&) { return {}; }
std::vector<DetectionResult> Scanner::scanFile(const std::string&) { return {}; }
std::vector<DetectionResult> Scanner::scanRepo() { return {}; }
std::vector<DetectionResult> Scanner::scanLine(const std::string&, int, const std::string&) { return {}; }
int Scanner::scoreResult(const std::string&, int base, double) { return base; }