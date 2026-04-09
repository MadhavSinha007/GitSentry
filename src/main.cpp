#include <iostream>
#include <string>
#include <filesystem>
#include "cli.h"
#include "scanner.h"

std::string resolveConfigPath() {
    namespace fs = std::filesystem;

    // 1. Local repo config
    if (fs::exists("config/patterns.json"))
        return "config/patterns.json";

    // 2. Global install config (FIXED NAME)
    if (fs::exists("/usr/local/share/GitSentry/patterns.json"))
        return "/usr/local/share/GitSentry/patterns.json";

    std::cerr << "[GitSentry] ERROR: Config file not found!\n";
    exit(1);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:  <command>\n"
                  << "  install     Install git hooks\n"
                  << "  uninstall   Remove git hooks\n"
                  << "  scan        Scan staged changes\n"
                  << "  scan --full Scan entire repo\n"
                  << "  config      Show current config\n";
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "install")   return CLI::installHooks();
    if (cmd == "uninstall") return CLI::uninstallHooks();
    if (cmd == "config")    return CLI::showConfig();

    if (cmd == "scan") {
        bool full = (argc > 2 && std::string(argv[2]) == "--full");

        std::string configPath = resolveConfigPath();  // ✅ FIXED
        Scanner scanner(configPath);

        return scanner.run(full);
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
}