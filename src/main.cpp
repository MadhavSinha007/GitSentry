#include <iostream>
#include <string>
#include <filesystem>
#include "cli.h"
#include "scanner.h"

// Resolve config path — check local first, then system-wide install
std::string resolveConfigPath()
{
    namespace fs = std::filesystem;

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

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "GitSentry — secret detection for git repos\n\n"
                  << "Usage: GitSentry <command>\n\n"
                  << "Commands:\n"
                  << "  install       Install pre-commit and pre-push hooks\n"
                  << "  uninstall     Remove git hooks\n"
                  << "  scan          Scan staged changes (used by pre-commit)\n"
                  << "  scan --full   Scan entire repository (used by pre-push)\n"
                  << "  scan --json   Scan staged changes and output JSON\n"
                  << "  config        Show current patterns config\n"
                  << "  --version     Show version\n";
        return 0;
    }

    std::string cmd = argv[1];

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

        for (int i = 2; i < argc; i++)
        {
            std::string arg = argv[i];
            if (arg == "--full")
                full = true;
            else if (arg == "--json")
                jsonOut = true;
        }

        std::string configPath = resolveConfigPath();
        if (configPath.empty())
            return 1;

        Scanner scanner(configPath);
        return scanner.run(full, jsonOut);
    }

    std::cerr << "[GitSentry] Unknown command: " << cmd << "\n";
    std::cerr << "Run 'GitSentry' with no arguments to see usage.\n";
    return 1;
}