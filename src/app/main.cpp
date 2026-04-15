#include <iostream>
#include <string>
#include <filesystem>
#include <cstdlib>
#include "cli.h"
#include "scanner.h"

// Resolve config path — env var first, then local, then system-wide install
std::string resolveConfigPath()
{
    namespace fs = std::filesystem;

    if (const char *envPath = std::getenv("GITSENTRY_CONFIG"))
    {
        if (fs::exists(envPath))
            return envPath;
    }

    if (fs::exists("config/patterns.json"))
        return "config/patterns.json";

    if (fs::exists("/usr/local/share/GitSentry/patterns.json"))
        return "/usr/local/share/GitSentry/patterns.json";

    std::cerr << "[GitSentry] ERROR: Config file not found!\n";
    std::cerr << "  Looked in: config/patterns.json\n";
    std::cerr << "  Looked in: /usr/local/share/GitSentry/patterns.json\n";
    std::cerr << "  Fix: sudo make install\n";
    return "";
}

void printHelp()
{
    std::cout << "GitSentry — secret detection for git repos\n\n"
              << "Usage: GitSentry <command>\n\n"
              << "Commands:\n"
              << "  install                         Install pre-commit and pre-push hooks\n"
              << "  uninstall                       Remove git hooks\n"
              << "  scan                            Scan staged changes (used by pre-commit)\n"
              << "  scan --full                     Scan entire repository (used by pre-push)\n"
              << "  scan --json                     Scan staged changes and output JSON\n"
              << "  scan --history                  Scan full git history\n"
              << "  scan --history --since=<time>   Scan git history since a time\n"
              << "  scan --fix                      Scan staged changes and interactively remove detected lines\n"
              << "  config                          Show current patterns config\n"
              << "  help, --help, -h                Show help\n"
              << "  --version, -v                   Show version\n";
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printHelp();
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "help" || cmd == "--help" || cmd == "-h")
    {
        printHelp();
        return 0;
    }

    if (cmd == "--version" || cmd == "-v")
    {
        std::cout << "GitSentry v0.2.0\n";
        return 0;
    }

    if (cmd == "install")
        return CLI::installHooks();

    if (cmd == "uninstall")
        return CLI::uninstallHooks();

    if (cmd == "config")
        return CLI::showConfig();

    if (cmd == "scan")
    {
        bool full = false;
        bool jsonOut = false;
        bool history = false;
        bool fixMode = false;
        std::string sinceArg;

        for (int i = 2; i < argc; i++)
        {
            std::string arg = argv[i];

            if (arg == "--full")
                full = true;
            else if (arg == "--json")
                jsonOut = true;
            else if (arg == "--history")
                history = true;
            else if (arg == "--fix")
                fixMode = true;
            else if (arg.rfind("--since=", 0) == 0)
                sinceArg = arg.substr(8);
        }

        if (!sinceArg.empty() && !history)
        {
            std::cerr << "[GitSentry] ERROR: --since requires --history\n";
            return 1;
        }

        if (fixMode && (full || history || jsonOut))
        {
            std::cerr << "[GitSentry] ERROR: --fix only supports staged scan mode right now\n";
            return 1;
        }

        std::string configPath = resolveConfigPath();
        if (configPath.empty())
            return 1;

        Scanner scanner(configPath);
        return scanner.run(full, jsonOut, history, sinceArg, fixMode);
    }

    std::cerr << "[GitSentry] Unknown command: " << cmd << "\n";
    std::cerr << "Run 'GitSentry help' to see usage.\n";
    return 1;
}