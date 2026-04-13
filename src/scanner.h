#pragma once
#include <string>
#include <vector>
#include <regex>
#include "json.hpp"

struct DetectionResult {
    std::string file;
    int line;
    std::string patternName;
    std::string masked;
    int score;
};

struct ScanStatsResult {
    std::vector<DetectionResult> detections;
    int filesScanned = 0;
    int linesScanned = 0;
};

class Scanner {
public:
    explicit Scanner(const std::string& configPath);
    int run(bool fullScan, bool jsonOutput = false);

private:
    nlohmann::json config_;

    struct CompiledPattern {
        std::string name;
        std::regex re;
        int confidence;
    };

    std::vector<CompiledPattern> patterns_;
    double entropyThreshold_;

    std::vector<DetectionResult> scanRepo(int& filesScanned, int& linesScanned);
    std::vector<DetectionResult> scanDiff(const std::string& diff, int& filesScanned, int& linesScanned);
    ScanStatsResult scanFile(const std::string& path);
    std::vector<DetectionResult> scanLine(
        const std::string& file, int lineNum, const std::string& line);

    int scoreResult(const std::string& line, int baseConf, double entropy);
};