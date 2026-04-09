#pragma once
#include <string>
#include <vector>

std::string maskSecret(const std::string& s);
std::string runCommand(const std::string& cmd);
std::vector<std::string> splitLines(const std::string& s);
bool pathMatchesIgnore(const std::string& path,
                       const std::vector<std::string>& patterns);
