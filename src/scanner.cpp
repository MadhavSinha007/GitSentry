#include "scanner.h"
#include "entropy.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include <regex>

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

