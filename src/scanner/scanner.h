#pragma once
#include <string>
#include <vector>
#include <regex>
#include "json.hpp"

struct DetectionResult
{
    std::string file;
    int line;
    std::string patternName;
    std::string masked;
    int score;
    std::string severity;
    std::string fingerprint;
};

struct ScanStatsResult
{
    std::vector<DetectionResult> detections;
    int filesScanned = 0;
    int linesScanned = 0;
};

class Scanner
{
public:
    explicit Scanner(const std::string &configPath);

    int run(bool fullScan,
            bool jsonOutput = false,
            bool historyScan = false,
            const std::string &since = "",
            bool fixMode = false,
            bool diffMode = false,
            bool pushMode = false);

    ScanStatsResult scanHistory(const std::string &since = "");
    int saveBaseline(const std::string &path = ".gitsentry_baseline");

private:
    struct CompiledPattern
    {
        std::string name;
        std::regex re;
        int confidence = 0;
        std::string severity = "info";
    };

    struct GenericDetector
    {
        std::string name;
        std::string type; // quoted_string_entropy | assignment_value_entropy | regex_entropy
        std::regex re;
        int minLength = 16;
        double minEntropy = 4.5;
        int baseConfidence = 60;
        std::string severity = "warning";
        bool requireSensitiveContext = false;
        std::vector<std::string> variableKeywords;
        std::vector<std::string> denyVariableNames;
    };

    nlohmann::json config_;
    std::vector<CompiledPattern> patterns_;
    std::vector<GenericDetector> genericDetectors_;
    std::vector<std::regex> allowlistRegexes_;
    std::vector<std::string> sensitiveVariableKeywords_;
    std::vector<std::string> testValueKeywords_;

    double entropyThreshold_ = 4.5;
    int minStringLength_ = 16;
    int blockScoreThreshold_ = 85;
    int warnScoreThreshold_ = 65;

    std::vector<DetectionResult> scanRepo(int &filesScanned, int &linesScanned);
    std::vector<DetectionResult> scanDiff(const std::string &diff, int &filesScanned, int &linesScanned);
    std::vector<DetectionResult> scanPushDiff(int &filesScanned, int &linesScanned);
    ScanStatsResult scanFile(const std::string &path);
    std::vector<DetectionResult> scanLine(
        const std::string &file, int lineNum, const std::string &line);

    int scoreResult(const std::string &line,
                    int baseConf,
                    double entropy,
                    bool sensitiveContext = false,
                    bool testContext = false) const;
};