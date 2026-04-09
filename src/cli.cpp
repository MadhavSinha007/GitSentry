#include "cli.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <cstdlib>

static void writeHook(const std::string& path, const std::string& body) {
    std::ofstream f(path);
    f << body;
    f.close();
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_exec |
        std::filesystem::perms::group_exec |
        std::filesystem::perms::others_exec,
        std::filesystem::perm_options::add);
}

int CLI::installHooks() {
    writeHook(".git/hooks/pre-commit",
        "#!/bin/sh\nGitSentry scan\n");
    writeHook(".git/hooks/pre-push",
        "#!/bin/sh\nGitSentry scan --full\n");
    std::cout << "[GitSentry] Hooks installed.\n";
    return 0;
}

int CLI::uninstallHooks(){
    std::filesystem::remove(".git/hooks/pre-commit");
    std::filesystem::remove("./git/hooks/pre-push");
    std::cout<< "[GitSentry] Hooks removed.\n";
    return 0;
}

int CLI::showConfig(){
    std::cout << "[GitSentry] Config: config/patterns.json\n";
    return 0;
}