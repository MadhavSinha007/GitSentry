// src/utils.h
#pragma once
#include <string>
#include <vector>
#include <unistd.h>

std::string maskSecret(const std::string& s);
std::string runCommand(const std::string& cmd);
std::vector<std::string> splitLines(const std::string& s);
bool pathMatchesIgnore(const std::string& path,
                       const std::vector<std::string>& patterns);

inline bool isTTY() { return isatty(STDOUT_FILENO); }
inline std::string red(const std::string& s) {
    return isTTY() ? "\033[31m" + s + "\033[0m" : s;
}
inline std::string green(const std::string& s) {
    return isTTY() ? "\033[32m" + s + "\033[0m" : s;
}
inline std::string yellow(const std::string& s) {
    return isTTY() ? "\033[33m" + s + "\033[0m" : s;
}
inline std::string bold(const std::string& s) {
    return isTTY() ? "\033[1m" + s + "\033[0m" : s;
}