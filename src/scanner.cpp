#include "scanner.h"
#include "entropy.h"
#include "utils.h"
#include "threadpool.h"

#include <iostream>
#include <fstream>
#include <regex>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <future>
#include <algorithm>
#include <chrono>

// Load extra ignore paths from .gitsentryignore
static std::vector<std::string> loadIgnoreFile() {
    std::vector<std::string> extra;
    std::ifstream f(".gitsentryignore");

    if (!f.is_open()) return extra;

    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line[0] != '#') {
            extra.push_back(line);
        }
    }

    return extra;
}

// Merge config ignores + .gitsentryignore + default ignores
static std::vector<std::string> buildIgnoreList(const nlohmann::json& config) {
    std::vector<std::string> ignores;

    if (config.contains("ignore_paths") && config["ignore_paths"].is_array()) {
        ignores = config["ignore_paths"].get<std::vector<std::string>>();
    }

    ignores.push_back(".git/");

    auto extra = loadIgnoreFile();
    ignores.insert(ignores.end(), extra.begin(), extra.end());

    return ignores;
}

// Constructor — load config + compile patterns
Scanner::Scanner(const std::string& cfgPath) {
    if (cfgPath.empty()) {
        std::cerr << "[GitSentry] ERROR: empty config path.\n";
        return;
    }

    std::ifstream f(cfgPath);
    if (!f.is_open()) {
        std::cerr << "[GitSentry] ERROR: cannot open config: " << cfgPath << "\n";
        return;
    }

    try {
        config_ = nlohmann::json::parse(f);
    } catch (const std::exception& e) {
        std::cerr << "[GitSentry] ERROR: invalid JSON in config: " << e.what() << "\n";
        return;
    }

    entropyThreshold_ = config_.value("entropy_threshold", 4.5);

    if (config_.contains("patterns") && config_["patterns"].is_array()) {
        for (auto& p : config_["patterns"]) {
            try {
                patterns_.push_back({
                    p["name"].get<std::string>(),
                    std::regex(
                        p["regex"].get<std::string>(),
                        std::regex::ECMAScript | std::regex::optimize
                    ),
                    p["confidence"].get<int>()
                });
            } catch (const std::regex_error& e) {
                std::cerr << "[GitSentry] WARNING: bad regex for pattern '"
                          << p["name"] << "': " << e.what() << " — skipping.\n";
            }
        }
    }
}

// Scoring — context boost, test penalty, entropy
int Scanner::scoreResult(const std::string& line,
                         int baseConf, double entropy) {
    int score = baseConf;

    std::string low = line;
    for (char& c : low) c = std::tolower((unsigned char)c);

    for (auto& kw : {"key", "token", "secret", "password", "credential", "auth", "api"}) {
        if (low.find(kw) != std::string::npos) {
            score += 10;
            break;
        }
    }

    for (auto& kw : {"test", "example", "dummy", "fake", "placeholder", "sample", "mock", "your_"}) {
        if (low.find(kw) != std::string::npos) {
            score -= 20;
            break;
        }
    }

    if (entropy >= entropyThreshold_) score += 15;

    return score;
}

// run() — entry point for scan / scan --full
int Scanner::run(bool fullScan, bool jsonOutput) {
    auto start = std::chrono::high_resolution_clock::now();

    int filesScanned = 0;
    int linesScanned = 0;
    std::vector<DetectionResult> results;

    if (fullScan) {
        if (!jsonOutput)
            std::cout << "[GitSentry] Scanning entire repository...\n";
        results = scanRepo(filesScanned, linesScanned);
    } else {
        std::string diff = runCommand("git diff --cached --unified=0");

        if (diff.empty()) {
            auto end = std::chrono::high_resolution_clock::now();
            double ms = std::chrono::duration<double, std::milli>(end - start).count();

            if (jsonOutput) {
                std::cout << "{\n"
                          << "  \"status\": \"clean\",\n"
                          << "  \"secrets\": [],\n"
                          << "  \"summary\": {\n"
                          << "    \"files_scanned\": 0,\n"
                          << "    \"lines_scanned\": 0,\n"
                          << "    \"time_seconds\": " << (ms / 1000.0) << "\n"
                          << "  }\n"
                          << "}\n";
            } else {
                std::cout << "[GitSentry] No staged changes to scan.\n\n"
                          << "[GitSentry] Scan complete\n"
                          << "  Files scanned:  0\n"
                          << "  Lines scanned:  0\n"
                          << "  Time taken:     " << (ms / 1000.0) << "s\n"
                          << "  Secrets found:  0\n\n";
            }
            return 0;
        }

        results = scanDiff(diff, filesScanned, linesScanned);
    }

    std::sort(results.begin(), results.end(),
        [](const DetectionResult& a, const DetectionResult& b) {
            return a.file == b.file ? a.line < b.line : a.file < b.file;
        });

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    if (jsonOutput) {
        std::cout << "{\n"
                  << "  \"status\": \"" << (results.empty() ? "clean" : "blocked") << "\",\n"
                  << "  \"secrets\": [\n";

        for (size_t i = 0; i < results.size(); i++) {
            auto& r = results[i];
            std::cout << "    {\n"
                      << "      \"file\": \"" << r.file << "\",\n"
                      << "      \"line\": " << r.line << ",\n"
                      << "      \"pattern\": \"" << r.patternName << "\",\n"
                      << "      \"masked\": \"" << r.masked << "\",\n"
                      << "      \"score\": " << r.score << "\n"
                      << "    }" << (i + 1 < results.size() ? "," : "") << "\n";
        }

        std::cout << "  ],\n"
                  << "  \"summary\": {\n"
                  << "    \"files_scanned\": " << filesScanned << ",\n"
                  << "    \"lines_scanned\": " << linesScanned << ",\n"
                  << "    \"time_seconds\": " << (ms / 1000.0) << "\n"
                  << "  }\n"
                  << "}\n";

        return results.empty() ? 0 : 1;
    }

    if (results.empty()) {
        std::cout << green("[GitSentry] No secrets detected. Safe to commit.\n");
    } else {
        std::cerr << red("\n[GitSentry] BLOCKED — potential secrets detected:\n\n");

        std::string lastFile;
        for (auto& r : results) {
            if (r.file != lastFile) {
                std::cerr << bold("  " + r.file + "\n");
                lastFile = r.file;
            }

            std::cerr << yellow("    Line " + std::to_string(r.line))
                      << "  [" << r.patternName << "]"
                      << "  score=" << r.score << "\n"
                      << "    " << r.masked << "\n\n";
        }

        std::cerr << "[GitSentry] Commit blocked. Fix the above before committing.\n";
    }

    std::cout << "\n[GitSentry] Scan complete\n"
              << "  Files scanned:  " << filesScanned << "\n"
              << "  Lines scanned:  " << linesScanned << "\n"
              << "  Time taken:     " << (ms / 1000.0) << "s\n"
              << "  Secrets found:  " << results.size() << "\n\n";

    return results.empty() ? 0 : 1;
}

// scanDiff() — staged diff scan with stats
std::vector<DetectionResult> Scanner::scanDiff(const std::string& diff, int& filesScanned, int& linesScanned) {
    std::vector<DetectionResult> results;
    std::vector<std::string> ignores = buildIgnoreList(config_);

    std::string currentFile;
    int lineNum = 0;
    bool currentFileCounted = false;

    std::regex hunkHeader(R"(^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@)");

    for (auto& line : splitLines(diff)) {
        if (line.rfind("+++ b/", 0) == 0) {
            currentFile = line.substr(6);
            lineNum = 0;
            currentFileCounted = false;

            if (pathMatchesIgnore(currentFile, ignores)) {
                currentFile.clear();
            }

            continue;
        }

        if (line.rfind("--- ", 0) == 0) continue;

        std::smatch m;
        if (std::regex_search(line, m, hunkHeader)) {
            lineNum = std::stoi(m[1].str()) - 1;
            continue;
        }

        if (line.empty()) continue;
        if (currentFile.empty()) continue;

        if (line[0] == '+' && (line.size() < 2 || line[1] != '+')) {
            ++lineNum;
            ++linesScanned;

            if (!currentFileCounted) {
                ++filesScanned;
                currentFileCounted = true;
            }

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

        } else if (line[0] == '-') {
            continue;
        } else {
            ++lineNum;
        }
    }

    return results;
}

// scanFile() — scan one file and return local stats
ScanStatsResult Scanner::scanFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};

    ScanStatsResult result;
    result.filesScanned = 1;

    std::string line;
    int lineNum = 0;

    while (std::getline(f, line)) {
        ++lineNum;
        ++result.linesScanned;

        auto hits = scanLine(path, lineNum, line);
        result.detections.insert(result.detections.end(), hits.begin(), hits.end());
    }

    return result;
}

// scanLine() — core detection per line
std::vector<DetectionResult> Scanner::scanLine(
    const std::string& file, int lineNum, const std::string& line) {

    std::vector<DetectionResult> results;

    for (const auto& pat : patterns_) {
        std::smatch match;

        if (!std::regex_search(line, match, pat.re)) continue;

        std::string found = match.str();

        if (pat.confidence < 80 && !isAlphanumericHeavy(found)) continue;

        double entropy = shannonEntropy(found);
        int score = scoreResult(line, pat.confidence, entropy);

        if (score < 50) continue;

        std::string masked = maskSecret(found);
        results.push_back({ file, lineNum, pat.name, masked, score });

        if (score > 90) return results;
    }

    return results;
}

// scanRepo() — parallel full-repo scan with thread-safe stats
std::vector<DetectionResult> Scanner::scanRepo(int& filesScanned, int& linesScanned) {
    namespace fs = std::filesystem;

    size_t threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 4;

    ThreadPool pool(threads);
    std::vector<std::future<ScanStatsResult>> futures;
    std::vector<std::string> ignores = buildIgnoreList(config_);

    for (auto& entry : fs::recursive_directory_iterator(
             ".", fs::directory_options::skip_permission_denied)) {

        if (!entry.is_regular_file()) continue;

        std::string path = entry.path().string();

        if (pathMatchesIgnore(path, ignores)) continue;
        if (entry.file_size() > 1'000'000) continue;

        {
            std::ifstream probe(path, std::ios::binary);
            char buf[512];
            probe.read(buf, sizeof(buf));
            auto n = probe.gcount();
            if (std::memchr(buf, '\0', static_cast<size_t>(n)) != nullptr)
                continue;
        }

        futures.push_back(pool.enqueue([this, path]() -> ScanStatsResult {
            return scanFile(path);
        }));
    }

    std::vector<DetectionResult> all;

    for (auto& f : futures) {
        auto res = f.get();
        filesScanned += res.filesScanned;
        linesScanned += res.linesScanned;
        all.insert(all.end(), res.detections.begin(), res.detections.end());
    }

    return all;
}