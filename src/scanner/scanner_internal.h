#pragma once
#include <string>
#include <vector>
#include "json.hpp"

// scanner private helpers shared across scanner_*.cpp
std::vector<std::string> loadIgnoreFile();
std::vector<std::string> buildIgnoreList(const nlohmann::json& config);