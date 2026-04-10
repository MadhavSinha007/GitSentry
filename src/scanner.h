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

class Scanner {
public:
    explicit Scanner(const std::string& configPath);
    int run(bool fullScan);

private:
    nlohmann::json config_;

    struct CompiledPattern {
        std::string name;
        std::regex re;
        int confidence;
    };

    std::vector<CompiledPattern> patterns_;
    double entropyThreshold_;

    std::vector<DetectionResult> scanRepo();
    std::vector<DetectionResult> scanDiff(const std::string& diff);
    std::vector<DetectionResult> scanFile(const std::string& path);
    std::vector<DetectionResult> scanLine(
        const std::string& file, int lineNum, const std::string& line);

    int scoreResult(const std::string& line, int baseConf, double entropy);
};