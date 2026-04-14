#include "scanner.h"
#include "utils.h"

#include <iostream>
#include <algorithm>
#include <chrono>

// run() — entry point for scan / scan --full / scan --history
int Scanner::run(bool fullScan, bool jsonOutput,
                 bool historyScan,
                 const std::string& since){
    auto start = std::chrono::high_resolution_clock::now();

    int filesScanned = 0;
    int linesScanned = 0;
    std::vector<DetectionResult> results;

    if (historyScan) {
        auto history = scanHistory(since);
        filesScanned = history.filesScanned;
        linesScanned = history.linesScanned;
        results = std::move(history.detections);

    } else if (fullScan) {
        if (!jsonOutput) {
            std::cout << "[GitSentry] Scanning entire repository...\n";
        }
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
        if (historyScan) {
            std::cout << green("[GitSentry] No secrets detected in git history.\n");
        } else {
            std::cout << green("[GitSentry] No secrets detected. Safe to commit.\n");
        }
    } else {
        std::cerr << red("\n[GitSentry] BLOCKED — potential secrets detected:\n\n");

        std::string lastFile;
        for (const auto& r : results) {
            if (r.file != lastFile) {
                std::cerr << bold("  " + r.file + "\n");
                lastFile = r.file;
            }

            std::cerr << yellow("    Line " + std::to_string(r.line))
                      << "  [" << r.patternName << "]"
                      << "  score=" << r.score << "\n"
                      << "    " << r.masked << "\n\n";
        }

        if (historyScan) {
            std::cerr << "[GitSentry] Secrets found in git history.\n";
        } else {
            std::cerr << "[GitSentry] Commit blocked. Fix the above before committing.\n";
        }
    }

    std::cout << "\n[GitSentry] Scan complete\n"
              << "  Files scanned:  " << filesScanned << "\n"
              << "  Lines scanned:  " << linesScanned << "\n"
              << "  Time taken:     " << (ms / 1000.0) << "s\n"
              << "  Secrets found:  " << results.size() << "\n\n";

    return results.empty() ? 0 : 1;
}