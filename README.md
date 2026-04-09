# GitSentry

A high-performance local secret detection tool that prevents sensitive credentials from being committed to Git repositories.

---

## Phase 1 — Core CLI & Hook System

### What's built
- CLI command parser (`install`, `uninstall`, `scan`, `scan --full`, `config`)
- Git hook installer that writes `pre-commit` and `pre-push` hooks automatically
- Project skeleton with `patterns.json` config, utilities, and build system

### Requirements
- g++ with C++17 support
- GNU Make
- Git

### Build & Install

```bash
git clone <your-repo-url>
cd GitSentry
make
sudo make install
```

### Usage

```bash
# Install hooks into a git repo
cd /path/to/your/repo
GitSentry install

# Scan staged changes before commit
GitSentry scan

# Scan entire repository
GitSentry scan --full

# Remove hooks
GitSentry uninstall

# Show config
GitSentry config
```

### How it works

When you run `GitSentry install` inside a git repository, it writes two hook scripts:

- `.git/hooks/pre-commit` — runs `GitSentry scan` on every `git commit`
- `.git/hooks/pre-push` — runs `GitSentry scan --full` on every `git push`

If a secret is detected, the hook exits with code `1` which causes git to abort the operation.

### Project Structure

GitSentry/
├── src/
│   ├── main.cpp       ← CLI entry point
│   ├── cli.cpp        ← hook installer / uninstaller
│   ├── cli.h
│   ├── scanner.cpp    ← detection engine (stub in Phase 1)
│   ├── scanner.h
│   ├── utils.cpp      ← masking, shell exec, helpers
│   └── utils.h
├── config/
│   └── patterns.json  ← regex rules and entropy config
├── third_party/
│   └── json.hpp       ← nlohmann/json (header-only)
├── Makefile
└── README.md

