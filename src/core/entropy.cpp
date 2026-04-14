#include "entropy.h"
#include <cmath>
#include <map>
#include <cctype>

double shannonEntropy(const std::string& s) {
    if (s.empty()) return 0.0;
    std::map<char,int> freq;
    for (char c : s) freq[c]++;
    double H = 0.0;
    double n = s.size();
    for (auto& [c, cnt] : freq) {
        double p = cnt / n;
        H -= p * std::log2(p);
    }
    return H;
}

bool isAlphanumericHeavy(const std::string& s) {
    int alnum = 0;
    for (char c : s)
        if (std::isalnum((unsigned char)c)) alnum++;
    return s.size() >= 16 && (double)alnum / s.size() >= 0.7;
}