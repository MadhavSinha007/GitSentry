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
#include <algorithm>
#include <unordered_set>

namespace
{

// ─────────────────────────────────────────────
// Shared regex compile flags
// icase  → case-insensitive matching (KEY = key = Key)
// ─────────────────────────────────────────────
static constexpr auto REGEX_FLAGS =
    std::regex::ECMAScript |
    std::regex::optimize   |
    std::regex::icase;

// Same flags but WITHOUT icase — used for:
// - allowlist regexes (exact case matters, e.g. AKIAIOSFODNN7EXAMPLE)
// - hex hash check (only lowercase hex is valid)
static constexpr auto REGEX_FLAGS_EXACT =
    std::regex::ECMAScript |
    std::regex::optimize;

std::string toLowerCopy(const std::string &s)
{
    std::string out = s;
    for (char &c : out)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool containsAnyKeyword(const std::string &haystackLower,
                        const std::vector<std::string> &keywords)
{
    for (const auto &kw : keywords)
    {
        if (!kw.empty() && haystackLower.find(toLowerCopy(kw)) != std::string::npos)
            return true;
    }
    return false;
}

bool matchesAnyRegex(const std::string &value,
                     const std::vector<std::regex> &regexes)
{
    for (const auto &re : regexes)
    {
        if (std::regex_match(value, re))
            return true;
    }
    return false;
}
std::string firstCapturedOrFull(const std::smatch &m)
{
    if (m.size() > 1 && m[1].matched)
        return m[1].str();
    return m.str();
}

bool isProbablyPlaceholder(const std::string &valueLower,
                           const std::vector<std::string> &testKeywords)
{
    return containsAnyKeyword(valueLower, testKeywords);
}

bool looksLikeHexHash(const std::string &value)
{
    // exact — hex hashes are always lowercase
    static const std::regex hexHash(R"(^[a-f0-9]{32,128}$)", REGEX_FLAGS_EXACT);
    return std::regex_match(value, hexHash);
}

// FNV-1a 64-bit hash for stable fingerprints
std::string fnv1a64(const std::string &s)
{
    const uint64_t offset = 14695981039346656037ull;
    const uint64_t prime  = 1099511628211ull;

    uint64_t hash = offset;
    for (unsigned char c : s)
    {
        hash ^= c;
        hash *= prime;
    }

    std::ostringstream oss;
    oss << std::hex << hash;
    return oss.str();
}

std::string effectiveSeverity(const std::string &baseSeverity,
                              int score,
                              int blockScoreThreshold)
{
    if (baseSeverity == "critical")  return "critical";
    if (score >= blockScoreThreshold) return "critical";
    if (baseSeverity == "warning")   return "warning";
    if (score >= 65)                  return "warning";
    return "info";
}

} // namespace

// ─────────────────────────────────────────────
// Constructor — load ALL config fields
// ─────────────────────────────────────────────
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

    entropyThreshold_    = config_.value("entropy_threshold",    4.5);
    minStringLength_     = config_.value("min_string_length",     16);
    blockScoreThreshold_ = config_.value("block_score_threshold", 85);
    warnScoreThreshold_  = config_.value("warn_score_threshold",  65);

    if (config_.contains("sensitive_variable_keywords") &&
        config_["sensitive_variable_keywords"].is_array())
    {
        sensitiveVariableKeywords_ =
            config_["sensitive_variable_keywords"].get<std::vector<std::string>>();
    }

    if (config_.contains("test_value_keywords") &&
        config_["test_value_keywords"].is_array())
    {
        testValueKeywords_ =
            config_["test_value_keywords"].get<std::vector<std::string>>();
    }

    // ── Allowlist regexes ─────────────────────
    // Keep EXACT case — these are known safe values like AKIAIOSFODNN7EXAMPLE
    if (config_.contains("allowlist_regexes") &&
        config_["allowlist_regexes"].is_array())
    {
        for (const auto &r : config_["allowlist_regexes"])
        {
            try
            {
                allowlistRegexes_.emplace_back(
                    r.get<std::string>(),
                    REGEX_FLAGS_EXACT);    // FIX: exact case for allowlist
            }
            catch (const std::regex_error &e)
            {
                std::cerr << "[GitSentry] WARNING: bad allowlist regex: "
                          << e.what() << " — skipping.\n";
            }
        }
    }

    // ── Detection patterns ────────────────────
    // FIX: use REGEX_FLAGS (includes icase) so KEY=, Token=, SECRET= all match
    if (config_.contains("patterns") && config_["patterns"].is_array())
    {
        for (const auto &p : config_["patterns"])
        {
            try
            {
                patterns_.push_back({
                    p.at("name").get<std::string>(),
                    std::regex(p.at("regex").get<std::string>(),
                               REGEX_FLAGS),              // FIX: was missing icase
                    p.value("confidence", 60),
                    p.value("severity", "info")
                });
            }
            catch (const std::regex_error &e)
            {
                std::cerr << "[GitSentry] WARNING: bad regex for pattern '"
                          << p.value("name", "<unnamed>") << "': "
                          << e.what() << " — skipping.\n";
            }
            catch (const std::exception &e)
            {
                std::cerr << "[GitSentry] WARNING: invalid pattern entry: "
                          << e.what() << " — skipping.\n";
            }
        }
    }

    // ── Generic detectors ─────────────────────
    if (config_.contains("generic_detectors") && config_["generic_detectors"].is_array())
    {
        for (const auto &g : config_["generic_detectors"])
        {
            try
            {
                GenericDetector det;
                det.name                  = g.at("name").get<std::string>();
                det.type                  = g.at("type").get<std::string>();
                det.minLength             = g.value("min_length",             minStringLength_);
                det.minEntropy            = g.value("min_entropy",            entropyThreshold_);
                det.baseConfidence        = g.value("base_confidence",        60);
                det.severity              = g.value("severity",               "warning");
                det.requireSensitiveContext = g.value("require_sensitive_context", false);

                if (g.contains("variable_keywords") && g["variable_keywords"].is_array())
                    det.variableKeywords =
                        g["variable_keywords"].get<std::vector<std::string>>();

                if (g.contains("deny_if_variable_name_matches") &&
                    g["deny_if_variable_name_matches"].is_array())
                    det.denyVariableNames =
                        g["deny_if_variable_name_matches"].get<std::vector<std::string>>();

                std::string regexText;
                if (det.type == "quoted_string_entropy")
                {
                    regexText = R"((["'])([A-Za-z0-9_/\+=\.-]{16,})\1)";
                }
                else if (det.type == "assignment_value_entropy")
                {
                    // FIX: broader variable capture — matches KEY=, Token=, SECRET= etc.
                    regexText = R"(([A-Za-z_][A-Za-z0-9_\-\.]{0,63})\s*[:=]\s*["']?([A-Za-z0-9_/\+=\.-]{16,})["']?)";
                }
                else if (det.type == "regex_entropy")
                {
                    regexText = g.at("regex").get<std::string>();
                }
                else
                {
                    throw std::runtime_error("unknown detector type: " + det.type);
                }

                // FIX: use REGEX_FLAGS (icase) for generic detectors too
                det.re = std::regex(regexText, REGEX_FLAGS);
                genericDetectors_.push_back(std::move(det));
            }
            catch (const std::regex_error &e)
            {
                std::cerr << "[GitSentry] WARNING: bad generic detector regex for '"
                          << g.value("name", "<unnamed>") << "': "
                          << e.what() << " — skipping.\n";
            }
            catch (const std::exception &e)
            {
                std::cerr << "[GitSentry] WARNING: invalid generic detector entry: "
                          << e.what() << " — skipping.\n";
            }
        }
    }
}

// ─────────────────────────────────────────────
// scoreResult
// ─────────────────────────────────────────────
int Scanner::scoreResult(const std::string &line,
                         int baseConf,
                         double entropy,
                         bool sensitiveContext,
                         bool testContext) const
{
    int score = baseConf;

    std::string low = toLowerCopy(line);

    if (sensitiveContext || containsAnyKeyword(low, sensitiveVariableKeywords_))
        score += 12;

    if (testContext || containsAnyKeyword(low, testValueKeywords_))
        score -= 22;

    if (entropy >= entropyThreshold_)
        score += 15;
    else if (entropy >= entropyThreshold_ - 0.25)
        score += 8;

    if (low.find("bearer ")        != std::string::npos) score += 8;
    if (low.find("authorization")  != std::string::npos) score += 8;
    if (low.find("private key")    != std::string::npos) score += 12;

    if (score > 100) score = 100;
    if (score < 0)   score = 0;

    return score;
}

// ─────────────────────────────────────────────
// scanLine — per-line detection
// ─────────────────────────────────────────────
std::vector<DetectionResult> Scanner::scanLine(
    const std::string &file, int lineNum, const std::string &line)
{
    // Inline ignore comment — skip entire line
    if (line.find("// gitsentry:ignore") != std::string::npos ||
        line.find("#  gitsentry:ignore") != std::string::npos ||
        line.find("/* gitsentry:ignore") != std::string::npos)
    {
        return {};
    }

    std::vector<DetectionResult> results;
    std::unordered_set<std::string> seenFingerprints;

    const std::string lineLower         = toLowerCopy(line);
    const bool lineSensitiveContext     = containsAnyKeyword(lineLower, sensitiveVariableKeywords_);
    const bool lineTestContext          = containsAnyKeyword(lineLower, testValueKeywords_);

    // ── Lambda: validate + push a candidate ──
    auto maybePush = [&](const std::string &name,
                         const std::string &found,
                         int baseConf,
                         const std::string &baseSeverity,
                         bool sensitiveContext)
    {
        if (static_cast<int>(found.size()) < minStringLength_)
            return;

        // allowlist check — exact case
        if (matchesAnyRegex(found, allowlistRegexes_))
            return;

        const std::string foundLower = toLowerCopy(found);
        if (isProbablyPlaceholder(foundLower, testValueKeywords_))
            return;

        const double entropy = shannonEntropy(found);
        const int score = scoreResult(line, baseConf, entropy,
                                      sensitiveContext, lineTestContext);
        if (score < warnScoreThreshold_)
            return;

        const std::string sev = effectiveSeverity(baseSeverity, score, blockScoreThreshold_);
        const std::string fp  = fnv1a64(found);

        // deduplicate within same line
        if (!seenFingerprints.insert(fp).second)
            return;

        results.push_back({file, lineNum, name, maskSecret(found), score, sev, fp});
    };

    // ── 1. Strong vendor / explicit regex patterns ──
    for (const auto &pat : patterns_)
    {
        for (std::sregex_iterator it(line.begin(), line.end(), pat.re), end;
             it != end; ++it)
        {
            const std::smatch m = *it;
            std::string found = firstCapturedOrFull(m);
            if (found.empty()) continue;

            maybePush(pat.name, found, pat.confidence,
                      pat.severity, lineSensitiveContext);

            // early exit on very high confidence hit
            if (!results.empty() && results.back().score >= 95)
                return results;
        }
    }

    // ── 2. Generic entropy-based detectors ──
    for (const auto &det : genericDetectors_)
    {
        for (std::sregex_iterator it(line.begin(), line.end(), det.re), end;
             it != end; ++it)
        {
            const std::smatch m = *it;

            std::string candidate;
            bool sensitiveContext = lineSensitiveContext;

            if (det.type == "quoted_string_entropy")
            {
                if (m.size() < 3) continue;
                candidate = m[2].str();
                if (det.requireSensitiveContext && !lineSensitiveContext) continue;
            }
            else if (det.type == "assignment_value_entropy")
            {
                if (m.size() < 3) continue;
                std::string variable = toLowerCopy(m[1].str());
                candidate = m[2].str();

                bool varSensitive = containsAnyKeyword(variable, det.variableKeywords);
                sensitiveContext  = sensitiveContext || varSensitive;

                if (!det.denyVariableNames.empty() &&
                    containsAnyKeyword(variable, det.denyVariableNames))
                    continue;

                if (det.requireSensitiveContext && !sensitiveContext) continue;
            }
            else // regex_entropy
            {
                candidate = firstCapturedOrFull(m);
                if (det.requireSensitiveContext && !lineSensitiveContext) continue;
            }

            if (static_cast<int>(candidate.size()) < det.minLength)  continue;
            if (matchesAnyRegex(candidate, allowlistRegexes_))        continue;

            const std::string candidateLower = toLowerCopy(candidate);
            if (isProbablyPlaceholder(candidateLower, testValueKeywords_)) continue;

            double entropy = shannonEntropy(candidate);
            if (entropy < det.minEntropy) continue;

            // skip pure hex hashes without sensitive context
            if (looksLikeHexHash(candidate) && !sensitiveContext) continue;

            maybePush(det.name, candidate, det.baseConfidence,
                      det.severity, sensitiveContext);
        }
    }

    return results;
}