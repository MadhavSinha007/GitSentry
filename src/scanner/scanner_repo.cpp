#include "scanner.h"
#include "scanner_internal.h"
#include "threadpool.h"
#include "utils.h"

#include <fstream>
#include <cstring>
#include <filesystem>
#include <future>

// Load extra ignore paths from .gitsentryignore
std::vector<std::string> loadIgnoreFile() {
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
std::vector<std::string> buildIgnoreList(const nlohmann::json& config) {
    std::vector<std::string> ignores;

    if (config.contains("ignore_paths") && config["ignore_paths"].is_array()) {
        ignores = config["ignore_paths"].get<std::vector<std::string>>();
    }

    ignores.push_back(".git/");

    auto extra = loadIgnoreFile();
    ignores.insert(ignores.end(), extra.begin(), extra.end());

    return ignores;
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

        // Skip binary files
        {
            std::ifstream probe(path, std::ios::binary);
            char buf[512];
            probe.read(buf, sizeof(buf));
            auto n = probe.gcount();
            if (std::memchr(buf, '\0', static_cast<size_t>(n)) != nullptr) {
                continue;
            }
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