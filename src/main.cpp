#include <iostream>
#include <string>
#include "cli.h"
#include "scanner.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: GitSentry <command>\n"
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
        Scanner scanner("config/patterns.json");
        return scanner.run(full);
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
}