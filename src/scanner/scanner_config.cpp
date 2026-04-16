#include "scanner.h"
#include "scanner_internal.h"
#include "entropy.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <cctype>
#include <regex>

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

    std::string low = line;
    for (char &c : low)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    for (auto &kw : {"key", "token", "secret", "password", "credential", "auth", "api"})
    {
        if (low.find(kw) != std::string::npos)
        {
            score += 10;
            break;
        }
    }

    for (auto &kw : {"test", "example", "dummy", "fake", "placeholder", "sample", "mock", "your_"})
    {
        if (low.find(kw) != std::string::npos)
        {
            score -= 20;
            break;
        }
    }

    if (entropy >= entropyThreshold_)
        score += 15;

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

    std::vector<DetectionResult> results;

    for (const auto &pat : patterns_)
    {
        std::smatch match;
        if (!std::regex_search(line, match, pat.re))
            continue;

        std::string found = match.str();

        // Generic lower-confidence patterns need token-like structure
        if (pat.confidence < 80 && !isAlphanumericHeavy(found))
            continue;

        double entropy = shannonEntropy(found);
        int score = scoreResult(line, pat.confidence, entropy);

        if (score < 50)
            continue;

        std::string masked = maskSecret(found);
        results.push_back({
            file,
            lineNum,
            pat.name,
            masked,
            score,
            pat.severity
        });

        // Early exit for very strong matches
        if (score > 90)
            return results;
    }

    return results;
}