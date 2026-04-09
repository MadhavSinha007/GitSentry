#include "scanner.h"
#include "entropy.h"
#include "utils.h"
#include "threadpool.h"

#include <iostream>
#include <fstream>
#include <regex>
#include <cctype>
#include <filesystem>
#include <future>

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

    std::string low = line;
    for (char& c : low) c = std::tolower((unsigned char)c);

    // context boost
    for (auto& kw : {"key","token","secret","password","credential"})
        if (low.find(kw) != std::string::npos) {
            score += 10;
            break;
        }

    // test penalty
    for (auto& kw : {"test","example","dummy","fake","placeholder","sample"})
        if (low.find(kw) != std::string::npos) {
            score -= 20;
            break;
        }

    // entropy bonus
    if (entropy >= entropyThreshold_) score += 15;

    return score;
}

int Scanner::run(bool fullScan) {

    std::vector<DetectionResult> results;

    if (fullScan) {
        results = scanRepo();
    } else {
        std::string diff = runCommand("git diff --cached --unified=0");
        results = scanDiff(diff);
    }

    if (results.empty()) {
        std::cout << "[GitSentry] No potential secrets detected. Safe to commit.\n";
        return 0;
    }

    std::cerr << "\n[GitSentry] BLOCKED: secrets detected:\n";
    for (auto& r : results) {
        std::cerr << " " << r.file << ":" << r.line
                  << "  [" << r.patternName << "]\n"
                  << "  " << r.masked << "\n\n";
    }

    return 1;
}

std::vector<DetectionResult> Scanner::scanDiff(const std::string& diff) {
    std::vector<DetectionResult> results;
    std::string currentFile;
    int lineNum = 0;

    for (auto& line : splitLines(diff)) {
        if (line.rfind("+++ b/", 0) == 0) {
            currentFile = line.substr(6);
            lineNum = 0;
        }
        else if (line.size() > 1 && line[0] == '+' && line[1] != '+') {
            ++lineNum;

            bool hasCandidate = false;
            for (char c : line) {
                if (std::isalnum((unsigned char)c)) {
                    hasCandidate = true;
                    break;
                }
            }

            if (!hasCandidate) continue;

            auto hits = scanLine(currentFile, lineNum, line.substr(1));
            results.insert(results.end(), hits.begin(), hits.end());
        }
    }

    return results;
}

std::vector<DetectionResult> Scanner::scanFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};

    std::vector<DetectionResult> results;
    std::string line;
    int lineNum = 0;

    while (std::getline(f, line)) {
        ++lineNum;

        auto hits = scanLine(path, lineNum, line);
        results.insert(results.end(), hits.begin(), hits.end());
    }

    return results;
}

std::vector<DetectionResult> Scanner::scanLine(
    const std::string& file, int lineNum, const std::string& line) {

    std::vector<DetectionResult> results;

    for (const auto& pat : patterns_) {
        std::smatch match;

        if (std::regex_search(line, match, pat.re)) {

            std::string found = match.str();

        
            if (!isAlphanumericHeavy(found))
                continue;

            double entropy = shannonEntropy(found);

            int score = scoreResult(line, pat.confidence, entropy);

           
            std::string masked;
            if (found.length() > 8)
                masked = found.substr(0, 4) + "****" + found.substr(found.length() - 2);
            else
                masked = "****";

            results.push_back({
                file,
                lineNum,
                pat.name,
                masked,
                score
            });
        }
    }

    return results;
}

std::vector<DetectionResult> Scanner::scanRepo() {
    namespace fs = std::filesystem;

    size_t threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 4;

    ThreadPool pool(threads);

    std::vector<std::future<std::vector<DetectionResult>>> futures;

    std::vector<std::string> ignores =
        config_["ignore_paths"].get<std::vector<std::string>>();

    for (auto& entry : fs::recursive_directory_iterator(".")) {

        if (!entry.is_regular_file()) continue;

        std::string path = entry.path().string();

        if (pathMatchesIgnore(path, ignores)) continue;

        // skip large files (>1MB)
        if (entry.file_size() > 1e6) continue;

        futures.push_back(pool.enqueue([this, path]() {
            return scanFile(path);
        }));
    }

    std::vector<DetectionResult> all;

    for (auto& f : futures) {
        auto res = f.get();
        all.insert(all.end(), res.begin(), res.end());
    }

    return all;
}