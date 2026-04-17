#include "scanner.h"
#include "utils.h"

#include <iostream>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>

// Load baseline file into a set of known findings
static std::set<std::string> loadBaseline(const std::string& path)
{
    std::set<std::string> known;

    std::ifstream f(path);
    if (!f.is_open())
        return known;

    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty())
            known.insert(line);
    }

    return known;
}

// Save baseline of current full-repo findings
int Scanner::saveBaseline(const std::string& path)
{
    int filesScanned = 0;
    int linesScanned = 0;
    auto results = scanRepo(filesScanned, linesScanned);

    std::ofstream f(path);
    if (!f.is_open()) {
        std::cerr << "[GitSentry] ERROR: cannot write baseline file: " << path << "\n";
        return 1;
    }

    for (const auto& r : results) {
        f << r.file << ":" << r.patternName << ":" << r.fingerprint << "\n";
    }

    std::cout << "[GitSentry] Baseline saved: "
              << results.size() << " findings.\n";

    return 0;
}

// run() — entry point for scan / scan --full / scan --history / scan --fix / scan --diff / scan --push
int Scanner::run(bool fullScan,
                 bool jsonOutput,
                 bool historyScan,
                 const std::string& since,
                 bool fixMode,
                 bool diffMode,
                 bool pushMode) {
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

    } else if (pushMode) {
        if (!jsonOutput) {
            std::cout << "[GitSentry] Scanning pushed commits only...\n";
        }
        results = scanPushDiff(filesScanned, linesScanned);

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
                          << "  Findings:       0\n\n";
            }

            return 0;
        }

        results = scanDiff(diff, filesScanned, linesScanned);
    }

    if (diffMode) {
        auto known = loadBaseline(".gitsentry_baseline");
        std::vector<DetectionResult> filtered;

        for (const auto& r : results) {
            std::string key = r.file + ":" +
                              r.patternName + ":" +
                              r.fingerprint;

            if (known.count(key))
                continue;

            filtered.push_back(r);
        }

        results = std::move(filtered);
    }

    std::sort(results.begin(), results.end(),
        [](const DetectionResult& a, const DetectionResult& b) {
            return a.file == b.file ? a.line < b.line : a.file < b.file;
        });

    bool hasBlocker = false;
    for (const auto& r : results) {
        if (r.severity == "critical") {
            hasBlocker = true;
            break;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    if (jsonOutput) {
        std::cout << "{\n"
                  << "  \"status\": \"" << (hasBlocker ? "blocked" : "clean") << "\",\n"
                  << "  \"secrets\": [\n";

        for (size_t i = 0; i < results.size(); i++) {
            auto& r = results[i];
            std::cout << "    {\n"
                      << "      \"file\": \"" << r.file << "\",\n"
                      << "      \"line\": " << r.line << ",\n"
                      << "      \"pattern\": \"" << r.patternName << "\",\n"
                      << "      \"masked\": \"" << r.masked << "\",\n"
                      << "      \"score\": " << r.score << ",\n"
                      << "      \"severity\": \"" << r.severity << "\",\n"
                      << "      \"fingerprint\": \"" << r.fingerprint << "\"\n"
                      << "    }" << (i + 1 < results.size() ? "," : "") << "\n";
        }

        std::cout << "  ],\n"
                  << "  \"summary\": {\n"
                  << "    \"files_scanned\": " << filesScanned << ",\n"
                  << "    \"lines_scanned\": " << linesScanned << ",\n"
                  << "    \"time_seconds\": " << (ms / 1000.0) << "\n"
                  << "  }\n"
                  << "}\n";

        return hasBlocker ? 1 : 0;
    }

    std::set<std::string> modifiedFiles;

    if (results.empty()) {
        if (diffMode) {
            std::cout << green("[GitSentry] No new findings since baseline.\n");
        } else if (historyScan) {
            std::cout << green("[GitSentry] No secrets detected in git history.\n");
        } else if (pushMode) {
            std::cout << green("[GitSentry] No secrets detected in pushed commits.\n");
        } else {
            std::cout << green("[GitSentry] No secrets detected. Safe to commit.\n");
        }
    } else {
        std::cerr << "\n[GitSentry] Findings detected:\n\n";

        std::string lastFile;
        for (const auto& r : results) {
            if (r.file != lastFile) {
                std::cerr << bold("  " + r.file + "\n");
                lastFile = r.file;
            }

            std::string label;
            if (r.severity == "critical") {
                label = red("[CRITICAL]");
            } else if (r.severity == "warning") {
                label = yellow("[WARNING ]");
            } else {
                label = green("[INFO    ]");
            }

            std::cerr << "    " << label
                      << " Line " << r.line
                      << "  [" << r.patternName << "]"
                      << "  score=" << r.score << "\n"
                      << "    " << r.masked << "\n\n";

            if (fixMode) {
                std::cerr << "  Remove line " << r.line
                          << " from " << r.file << "? (y/n): ";

                char ans = 'n';
                std::cin >> ans;

                if (ans == 'y' || ans == 'Y') {
                    std::ifstream in(r.file);
                    if (!in.is_open()) {
                        std::cerr << "  Could not open file for reading.\n";
                        continue;
                    }

                    std::vector<std::string> lines;
                    std::string l;
                    while (std::getline(in, l)) {
                        lines.push_back(l);
                    }
                    in.close();

                    if (r.line > 0 && r.line <= static_cast<int>(lines.size())) {
                        lines.erase(lines.begin() + r.line - 1);

                        std::ofstream out(r.file);
                        if (!out.is_open()) {
                            std::cerr << "  Could not open file for writing.\n";
                            continue;
                        }

                        for (const auto& ln : lines) {
                            out << ln << "\n";
                        }
                        out.close();

                        modifiedFiles.insert(r.file);
                        std::cerr << "  Line removed.\n";
                    } else {
                        std::cerr << "  Skipped: line number out of range in current file.\n";
                    }
                }
            }
        }

        if (fixMode && !modifiedFiles.empty()) {
            std::cerr << "\n[GitSentry] Re-stage modified files before committing:\n";
            for (const auto& file : modifiedFiles) {
                std::cerr << "  git add " << file << "\n";
            }
            std::cerr << "\n";
        }

        if (hasBlocker) {
            if (diffMode) {
                std::cerr << red("[GitSentry] New critical findings detected since baseline.\n");
            } else if (historyScan) {
                std::cerr << red("[GitSentry] Critical secrets found in git history.\n");
            } else if (pushMode) {
                std::cerr << red("[GitSentry] Push blocked due to critical findings in pushed commits.\n");
            } else {
                std::cerr << red("[GitSentry] Commit blocked due to critical findings.\n");
            }
        } else {
            if (diffMode) {
                std::cerr << yellow("[GitSentry] Only new warning/info findings detected since baseline.\n");
            } else if (pushMode) {
                std::cerr << yellow("[GitSentry] Only warning/info findings detected in pushed commits. Not blocking.\n");
            } else {
                std::cerr << yellow("[GitSentry] Only warning/info findings detected. Not blocking.\n");
            }
        }
    }

    std::cout << "\n[GitSentry] Scan complete\n"
              << "  Files scanned:  " << filesScanned << "\n"
              << "  Lines scanned:  " << linesScanned << "\n"
              << "  Time taken:     " << (ms / 1000.0) << "s\n"
              << "  Findings:       " << results.size() << "\n\n";

    return hasBlocker ? 1 : 0;
}