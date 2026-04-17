#include "scanner.h"
#include "utils.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <string>

// git pre-push hook stdin format:
//   <local ref> <local sha> <remote ref> <remote sha>
//
// Example:
//   refs/heads/main abc123 refs/heads/main def456
//
// For a new branch, remote sha is all zeroes.

static bool isZeroSha(const std::string& sha)
{
    return !sha.empty() &&
           sha.find_first_not_of('0') == std::string::npos;
}

std::vector<DetectionResult> Scanner::scanPushDiff(int& filesScanned, int& linesScanned)
{
    std::vector<std::string> ranges;
    std::string line;

    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            continue;
        }

        std::istringstream ss(line);
        std::string localRef, localSha, remoteRef, remoteSha;
        ss >> localRef >> localSha >> remoteRef >> remoteSha;

        if (localSha.empty()) {
            continue;
        }

        // New branch push: remote SHA is 0000000000000000000000000000000000000000
        // In that case, scan all commits reachable from localSha.
        if (isZeroSha(remoteSha)) {
            ranges.push_back(localSha);
        } else {
            ranges.push_back(remoteSha + ".." + localSha);
        }
    }

    if (ranges.empty()) {
        std::cerr << "[GitSentry] No pushed refs received on stdin.\n";
        return {};
    }

    // Build a single git log command that emits patch text only.
    // --format= suppresses commit headers so scanDiff() sees just patch content.
    std::string cmd = "git log -p --unified=0 --format=";
    for (const auto& r : ranges) {
        cmd += " " + r;
    }

    std::string diff = runCommand(cmd);
    if (diff.empty()) {
        return {};
    }

    return scanDiff(diff, filesScanned, linesScanned);
}