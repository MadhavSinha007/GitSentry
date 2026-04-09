
#include "utils.h"
#include <sstream>
#include <algorithm>
#include <cstdio>

std::string maskSecret(const std::string& s) {
    if (s.size() <= 8) return "****";
    return s.substr(0, 4) + "****" + s.substr(s.size() - 4);
}

std::string runCommand(const std::string& cmd) {
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
    pclose(pipe);
    return result;
}

std::vector<std::string> splitLines(const std::string& s) {
    std::vector<std::string> lines;
    std::istringstream ss(s);
    std::string line;
    while (std::getline(ss, line)) lines.push_back(line);
    return lines;
}

bool pathMatchesIgnore(const std::string& path,
                       const std::vector<std::string>& patterns) {
    for (auto& p : patterns)
        if (path.find(p) != std::string::npos) return true;
    return false;
}