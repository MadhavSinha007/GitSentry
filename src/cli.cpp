// src/cli.cpp  (installHooks excerpt)
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
    namespace fs = std::filesystem;

    if (!fs::exists(".git")) {
        std::cerr << "[GitSentry] ERROR: Not a git repository.\n";
        return 1;
    }

    fs::create_directories(".git/hooks");

    writeHook(".git/hooks/pre-commit",
        "#!/bin/sh\nGitSentry scan\n");

    writeHook(".git/hooks/pre-push",
        "#!/bin/sh\nGitSentry scan --full\n");

    std::cout << "[GitSentry] Hooks installed.\n";
    return 0;
}



int CLI::uninstallHooks() {
    namespace fs = std::filesystem;

    if (fs::exists(".git/hooks/pre-commit"))
        fs::remove(".git/hooks/pre-commit");

    if (fs::exists(".git/hooks/pre-push"))
        fs::remove(".git/hooks/pre-push");

    std::cout << "[GitSentry] hooks removed from project\n";
    return 0;
}


int CLI::showConfig() {
    std::ifstream f("config/patterns.json");

    if (!f.is_open()) {
        std::cerr << "[GitSentry] Could not open config.\n";
        return 1;
    }

    std::cout << f.rdbuf();
    return 0;
}