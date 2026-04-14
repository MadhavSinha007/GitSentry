#include "scanner.h"
#include "scanner_internal.h"
#include "utils.h"

#include <regex>
#include <cctype>
#include <iostream>

// scanDiff() — staged diff scan with file/line stats
std::vector<DetectionResult> Scanner::scanDiff(
    const std::string& diff,
    int& filesScanned,
    int& linesScanned) {

    std::vector<DetectionResult> results;
    std::vector<std::string> ignores = buildIgnoreList(config_);

    std::string currentFile;
    int lineNum = 0;
    bool currentFileCounted = false;

    std::regex hunkHeader(R"(^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@)");

    for (const auto& line : splitLines(diff)) {
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
                if (std::isalnum(static_cast<unsigned char>(c))) {
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


//combined patch stream version of scanDiff() for testing
ScanStatsResult Scanner::scanHistory(const std::string& since) {
    if (!config_.is_object()) {
        return {};
    }

    std::cout << "[GitSentry] Scanning git history";
    if (!since.empty()) {
        std::cout << " (since " << since << ")";
    }
    std::cout << "...\n";

    ScanStatsResult result;

    std::string cmd = "git log -p --all --unified=0 --format=";

    if (!since.empty()) {
        cmd = "git log -p --all --since=\"" + since + "\" --unified=0 --format=";
    }

    std::string diff = runCommand(cmd);

    if (diff.empty()) {
        return result;
    }

    result.detections = scanDiff(diff, result.filesScanned, result.linesScanned);
    return result;
}