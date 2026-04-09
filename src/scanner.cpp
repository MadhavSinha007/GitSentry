#include "scanner.h"
#include "entropy.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include <regex>
#include <cctype>

Scanner::Scanner(const std::string& cfgPath) {
    std::ifstream f(cfgPath);
    config_ = nlohmann::json::parse(f);
    entropyThreshold_ = config_["entropy_threshold"].get<double>();

    for (auto& p : config_["patterns"]) {
        patterns_.push_back({
            p["name"].get<std::string>(),
            std::regex(p["regex"].get<std::string>(),
                       std::regex::ECMAScript | std::regex::optimize),
            p["confidence"].get<int>()
        });
    }
}

int Scanner::scoreResult(const std::string& line,
                         int baseConf, double entropy) {
    int score = baseConf;
    // context boost
    std::string low = line;
    for (char& c : low) c = std::tolower((unsigned char)c);
    for (auto& kw : {"key","token","secret","password","credential"})
        if (low.find(kw) != std::string::npos) { score += 10; break; }
    // test penalty
    for (auto& kw : {"test","example","dummy","fake","placeholder","sample"})
        if (low.find(kw) != std::string::npos) { score -= 20; break; }
    // entropy bonus
    if (entropy >= entropyThreshold_) score += 15;
    return score;
}


int Scanner::run(bool fullScan){

    std::string diff = fullScan
    ? runCommand("git diff --cached")
    : runCommand("git diff --cached --unified=0");


    auto results = scanDiff(diff);
    if(results.empty()) {
        std::cout << "[GitSentry] No potential secrets detected. Safe to commit.\n";
        return 0;
    }

    std::cerr << "\n[GitSentry] BLOCKED: secrets detected in staged changes:\n";
    for(auto& r : results){
        std::cerr<< " " << r.file << ":" << r.lineNum 
        << "  [" << r.patternName << "]\n " <<
        "  " << r.masked << "\n\n";
    }

    return 1; //non-zero exit code to block commit
}

std::vector<DetectionResult> Scanner::scanDiff(const std::string& diff) {
    std::vector<DetectionResult> results;
    std::string currentFile;
    int lineNum = 0;
    for (auto& line : splitLines(diff)) {
        if (line.rfind("+++ b/", 0) == 0) {
            currentFile = line.substr(6);
            lineNum = 0;
        } else if (line.size() > 0 && line[0] == '+' && line[1] != '+') {
            ++lineNum;
            // pre-filter: skip lines without alphanumeric runs
            bool hasCandidate = false;
            for (char c : line) if (std::isalnum((unsigned char)c))
                { hasCandidate = true; break; }
            if (!hasCandidate) continue;

            auto hits = scanLine(currentFile, lineNum, line.substr(1));
            results.insert(results.end(), hits.begin(), hits.end());
        }
    }
    return results;
}