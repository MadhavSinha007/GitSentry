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

// Load extra ignore paths from .gitsentryignore
static std::vector<std::string> loadIgnoreFile() {
    std::vector<std::string> extra;
    std::ifstream f(".gitsentryignore");

    if (!f.is_open()) return extra;

    std::string line;
    while (std::getline(f, line)) {
        // Skip empty lines and comments
        if (!line.empty() && line[0] != '#') {
            extra.push_back(line);
        }
    }

    return extra;
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

// Scoring — context boost, test penalty, entropy
int Scanner::scoreResult(const std::string& line,
                         int baseConf, double entropy) {
    int score = baseConf;

    std::string low = line;
    for (char& c : low) c = std::tolower((unsigned char)c);

    // +10 if variable name suggests it's a secret
    for (auto& kw : {"key", "token", "secret", "password", "credential", "auth", "api"}) {
        if (low.find(kw) != std::string::npos) {
            score += 10;
            break;
        }
    }

    // -20 if line looks like test/example data
    for (auto& kw : {"test", "example", "dummy", "fake", "placeholder", "sample", "mock", "your_"}) {
        if (low.find(kw) != std::string::npos) {
            score -= 20;
            break;
        }
    }

    // +15 if the matched string has high entropy (looks random)
    if (entropy >= entropyThreshold_) score += 15;

    return score;
}

// run() — entry point for scan / scan --full
int Scanner::run(bool fullScan) {
    std::vector<DetectionResult> results;

    if (fullScan) {
        std::cout << "[GitSentry] Scanning entire repository...\n";
        results = scanRepo();
    } else {
        std::string diff = runCommand("git diff --cached --unified=0");
        if (diff.empty()) {
            std::cout << "[GitSentry] No staged changes to scan.\n";
            return 0;
        }
        results = scanDiff(diff);
    }

    if (results.empty()) {
        std::cout << green("[GitSentry] No secrets detected. Safe to commit.\n");
        return 0;
    }

    // Sort results by file then line number for readable output
    std::sort(results.begin(), results.end(),
        [](const DetectionResult& a, const DetectionResult& b) {
            return a.file == b.file ? a.line < b.line : a.file < b.file;
        });

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
    return 1;
}

// scanDiff() — real line numbers from @@ hunk headers
std::vector<DetectionResult> Scanner::scanDiff(const std::string& diff) {
    std::vector<DetectionResult> results;
    std::string currentFile;
    int lineNum = 0;

    // Matches: @@ -oldStart,count +newStart,count @@
    // We only care about the new-file start (group 1)
    std::regex hunkHeader(R"(^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@)");

    for (auto& line : splitLines(diff)) {
        // Track current file
        if (line.rfind("+++ b/", 0) == 0) {
            currentFile = line.substr(6);
            lineNum = 0;
            continue;
        }

        // Skip the old-file header
        if (line.rfind("--- ", 0) == 0) continue;

        // Extract real line number from hunk header
        std::smatch m;
        if (std::regex_search(line, m, hunkHeader)) {
            lineNum = std::stoi(m[1].str()) - 1; // -1 because we ++ before use
            continue;
        }

        if (line.empty()) continue;

        if (line[0] == '+' && (line.size() < 2 || line[1] != '+')) {
            // Added line — scan it
            ++lineNum;

            // Pre-filter: skip lines with no alphanumeric chars
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
            // Removed line — don't advance new-file line counter
            continue;
        } else {
            // Context line — advance counter
            ++lineNum;
        }
    }

    return results;
}

// scanFile() — used by scanRepo() (full scan)
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

// scanLine() — core detection per line
std::vector<DetectionResult> Scanner::scanLine(
    const std::string& file, int lineNum, const std::string& line) {

    std::vector<DetectionResult> results;

    for (const auto& pat : patterns_) {
        std::smatch match;

        if (!std::regex_search(line, match, pat.re)) continue;

        std::string found = match.str();

        // For low-confidence / generic patterns, require token-like structure.
        // For high-confidence known-secret regexes, trust the regex match itself.
        if (pat.confidence < 80 && !isAlphanumericHeavy(found)) continue;

        double entropy = shannonEntropy(found);
        int score = scoreResult(line, pat.confidence, entropy);

        // Ignore very low confidence results
        if (score < 50) continue;

        std::string masked = maskSecret(found);

        results.push_back({ file, lineNum, pat.name, masked, score });

        // Early exit — very high confidence hit, no need to keep checking
        if (score > 90) return results;
    }

    return results;
}

// scanRepo() — parallel full-repo scan
std::vector<DetectionResult> Scanner::scanRepo() {
    namespace fs = std::filesystem;

    size_t threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 4;

    ThreadPool pool(threads);
    std::vector<std::future<std::vector<DetectionResult>>> futures;

    std::vector<std::string> ignores =
        config_["ignore_paths"].get<std::vector<std::string>>();

    // Always ignore .git internals
    ignores.push_back(".git/");

    // Load additional ignore paths from .gitsentryignore
    auto fileIgnores = loadIgnoreFile();
    ignores.insert(ignores.end(), fileIgnores.begin(), fileIgnores.end());

    for (auto& entry : fs::recursive_directory_iterator(
             ".", fs::directory_options::skip_permission_denied)) {

        if (!entry.is_regular_file()) continue;

        std::string path = entry.path().string();

        if (pathMatchesIgnore(path, ignores)) continue;

        // Skip files larger than 1MB
        if (entry.file_size() > 1'000'000) continue;

        // Skip binary files — peek first 512 bytes for null bytes
        {
            std::ifstream probe(path, std::ios::binary);
            char buf[512];
            probe.read(buf, sizeof(buf));
            auto n = probe.gcount();
            if (std::memchr(buf, '\0', static_cast<size_t>(n)) != nullptr)
                continue;
        }

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