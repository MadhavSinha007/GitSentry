#include "scanner.h"
#include "scanner_internal.h"
#include "entropy.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <cctype>
#include <regex>
#include <sstream>
#include <cstdint>
#include <set>
#include <algorithm>

// Helper function to compute FNV-1a 64-bit hash of a string.
// Used for stable baseline fingerprinting without storing raw secrets.
static std::string fnv1a64(const std::string& s)
{
    const uint64_t offset = 14695981039346656037ull;
    const uint64_t prime  = 1099511628211ull;

    uint64_t hash = offset;
    for (unsigned char c : s) {
        hash ^= c;
        hash *= prime;
    }

    std::ostringstream oss;
    oss << std::hex << hash;
    return oss.str();
}

static std::string toLowerCopy(std::string s)
{
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

static bool containsAny(const std::string& haystack,
                        std::initializer_list<const char*> needles)
{
    for (const char* needle : needles) {
        if (haystack.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
}

static std::string effectiveSeverity(const std::string& configured, int score)
{
    std::string low = toLowerCopy(configured);

    if (low == "critical") {
        return "critical";
    }
    if (score >= 90) {
        return "critical";
    }
    if (low == "warning") {
        return "warning";
    }
    if (score >= 70) {
        return "warning";
    }
    return "info";
}

static bool looksLikeStructuredPlaceholder(const std::string& value)
{
    const std::string low = toLowerCopy(value);
    return containsAny(low, {
        "example", "dummy", "sample", "placeholder", "changeme",
        "replace_me", "replace-this", "your_", "your-", "test",
        "fake", "mock", "localhost"
    });
}

static bool looksLikeLikelyIdentifierOnly(const std::string& value)
{
    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSymbol = false;

    for (unsigned char c : value) {
        if (std::islower(c)) hasLower = true;
        else if (std::isupper(c)) hasUpper = true;
        else if (std::isdigit(c)) hasDigit = true;
        else hasSymbol = true;
    }

    // IDs that are purely simple alnum/underscore/hyphen are often not secrets.
    return !hasSymbol && value.size() < 40 && !(hasLower && hasUpper && hasDigit);
}

static std::string bestMaskedValue(const std::string& raw)
{
    std::string trimmed = raw;
    if (!trimmed.empty() &&
        ((trimmed.front() == '"' && trimmed.back() == '"') ||
         (trimmed.front() == '\'' && trimmed.back() == '\''))) {
        trimmed = trimmed.substr(1, trimmed.size() - 2);
    }
    return maskSecret(trimmed);
}

// Constructor — load config + compile patterns
Scanner::Scanner(const std::string &cfgPath)
{
    if (cfgPath.empty())
    {
        std::cerr << "[GitSentry] ERROR: empty config path.\n";
        return;
    }

    std::ifstream f(cfgPath);
    if (!f.is_open())
    {
        std::cerr << "[GitSentry] ERROR: cannot open config: " << cfgPath << "\n";
        return;
    }

    try
    {
        config_ = nlohmann::json::parse(f);
    }
    catch (const std::exception &e)
    {
        std::cerr << "[GitSentry] ERROR: invalid JSON in config: " << e.what() << "\n";
        return;
    }

    entropyThreshold_ = config_.value("entropy_threshold", 4.5);

    if (config_.contains("patterns") && config_["patterns"].is_array())
    {
        for (auto &p : config_["patterns"])
        {
            try
            {
                patterns_.push_back({
                    p["name"].get<std::string>(),
                    std::regex(
                        p["regex"].get<std::string>(),
                        std::regex::ECMAScript | std::regex::optimize),
                    p["confidence"].get<int>(),
                    p.value("severity", "info")
                });
            }
            catch (const std::regex_error &e)
            {
                std::cerr << "[GitSentry] WARNING: bad regex for pattern '"
                          << p["name"] << "': " << e.what() << " — skipping.\n";
            }
        }
    }
}

// Scoring — context boost, test penalty, entropy
int Scanner::scoreResult(const std::string &line, int baseConf, double entropy)
{
    int score = baseConf;

    std::string low = toLowerCopy(line);

    if (containsAny(low, {
        "key", "token", "secret", "password", "credential", "auth", "api",
        "bearer", "private", "client_secret", "access_token", "refresh_token",
        "jwt", "authorization"
    })) {
        score += 10;
    }

    if (containsAny(low, {
        "test", "example", "dummy", "fake", "placeholder", "sample", "mock",
        "your_", "your-", "changeme", "replace_me", "replace-this"
    })) {
        score -= 25;
    }

    if (entropy >= entropyThreshold_ + 0.8)
        score += 20;
    else if (entropy >= entropyThreshold_)
        score += 15;

    score = std::max(0, std::min(100, score));
    return score;
}

// scanLine() — core detection per line
std::vector<DetectionResult> Scanner::scanLine(
    const std::string &file, int lineNum, const std::string &line)
{
    // ignore line that have "// gitsentry:ignore"
    // /* gitsentry:ignore */ and # gitsentry:ignore are also supported
    if (line.find("// gitsentry:ignore") != std::string::npos ||
        line.find("# gitsentry:ignore") != std::string::npos ||
        line.find("/* gitsentry:ignore") != std::string::npos)
    {
        return {};
    }

    const int minStringLength = config_.value("min_string_length", 16);
    std::vector<DetectionResult> results;
    std::set<std::string> seen;

    for (const auto &pat : patterns_)
    {
        for (std::sregex_iterator it(line.begin(), line.end(), pat.re), end; it != end; ++it)
        {
            std::string found = it->str();
            if (static_cast<int>(found.size()) < minStringLength && pat.confidence < 90) {
                continue;
            }

            // Generic lower-confidence patterns need token-like structure
            if (pat.confidence < 80 && !isAlphanumericHeavy(found))
                continue;

            if (looksLikeStructuredPlaceholder(found)) {
                continue;
            }

            double entropy = shannonEntropy(found);
            int score = scoreResult(line, pat.confidence, entropy);

            if (score < 55)
                continue;

            std::string fingerprint = fnv1a64(found);
            if (!seen.insert(pat.name + ":" + fingerprint).second) {
                continue;
            }

            results.push_back({
                file,
                lineNum,
                pat.name,
                bestMaskedValue(found),
                score,
                effectiveSeverity(pat.severity, score),
                fingerprint
            });
        }
    }

    // Generic high-entropy quoted strings: catches secrets embedded in normal code.
    static const std::regex quotedString(
        R"((["'])([A-Za-z0-9_\-\./+=]{16,})\1)",
        std::regex::ECMAScript | std::regex::optimize);

    for (std::sregex_iterator it(line.begin(), line.end(), quotedString), end; it != end; ++it)
    {
        std::string candidate = (*it)[2].str();
        if (static_cast<int>(candidate.size()) < minStringLength) {
            continue;
        }
        if (!isAlphanumericHeavy(candidate)) {
            continue;
        }
        if (looksLikeStructuredPlaceholder(candidate)) {
            continue;
        }
        if (looksLikeLikelyIdentifierOnly(candidate)) {
            continue;
        }

        double entropy = shannonEntropy(candidate);
        if (entropy < entropyThreshold_) {
            continue;
        }

        int score = scoreResult(line, 65, entropy);
        if (score < 75) {
            continue;
        }

        std::string fingerprint = fnv1a64(candidate);
        if (!seen.insert(std::string("High Entropy String:") + fingerprint).second) {
            continue;
        }

        results.push_back({
            file,
            lineNum,
            "High Entropy String",
            maskSecret(candidate),
            score,
            effectiveSeverity("warning", score),
            fingerprint
        });
    }

    return results;
}