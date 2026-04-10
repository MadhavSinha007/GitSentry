![CI](https://github.com/MadhavSinha007/GitSentry/actions/workflows/ci.yml/badge.svg)

# GitSentry

A high-performance CLI tool written in C++ that prevents sensitive credentials from being committed to Git repositories. GitSentry runs completely offline and integrates directly into your Git workflow via hooks.

---

## How it works

When you run `GitSentry install` inside a Git repository, it installs two hooks:

- **pre-commit** — scans staged changes before every `git commit`
- **pre-push** — scans the entire repository before every `git push`

If a secret is detected, the hook exits with code `1` and Git aborts the operation. Nothing is sent anywhere — all scanning happens locally on your machine.

---

## Detection engine

GitSentry uses three layers of detection working together:

**Regex matching** — compiled once at startup from `patterns.json`. Covers AWS keys, GitHub tokens, Stripe keys, and generic API key patterns.

**Shannon entropy scoring** — measures how random a string looks. Real API keys score above 4.5. Human-readable words score around 3.0. Entropy is only calculated on strings that are 16+ characters and alphanumeric-heavy.

**Context analysis** — boosts or reduces confidence based on surrounding code. Variable names like `key`, `token`, `secret`, `password` add +10 to the score. Words like `test`, `example`, `dummy`, `fake` subtract -20. Only results scoring above 65 are reported.

---

## Project structure

```
GitSentry/
├── src/
│   ├── main.cpp          ← CLI entry point and command dispatcher
│   ├── cli.cpp           ← Hook installer and uninstaller
│   ├── cli.h
│   ├── scanner.cpp       ← Core detection engine
│   ├── scanner.h
│   ├── entropy.cpp       ← Shannon entropy calculation
│   ├── entropy.h
│   ├── threadpool.cpp    ← Thread pool for parallel scanning
│   ├── threadpool.h
│   ├── utils.cpp         ← Masking, shell exec, path helpers
│   └── utils.h
├── config/
│   └── patterns.json     ← Regex rules and detection config
├── third_party/
│   └── json.hpp          ← nlohmann/json (header-only)
├── tests/
│   └── test_scanner.cpp  ← Unit tests
├── scripts/
│   └── install.sh        ← One-line installer
├── Makefile
└── README.md
```

---

## Requirements

- g++ with C++17 support (`g++ --version` should show 7+)
- GNU Make
- Git

---

## Installation

```bash
git clone <your-repo-url>
cd GitSentry

# Download the JSON library (one time only)
curl -sSL https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp \
  -o third_party/json.hpp

# Build and install
make
sudo make install
```

This installs:
- The `GitSentry` binary to `/usr/local/bin/`
- The `patterns.json` config to `/usr/local/share/GitSentry/`

---

## Usage

```bash
# Install hooks into a git repository
cd /path/to/your/repo
GitSentry install

# Manually scan staged changes
GitSentry scan

# Manually scan the entire repository
GitSentry scan --full

# Remove hooks from current repository
GitSentry uninstall

# Show current patterns config
GitSentry config

# Show version
GitSentry --version
```

---

## Configuration

Edit `config/patterns.json` to add patterns or adjust thresholds:

```json
{
  "entropy_threshold": 4.5,
  "min_string_length": 16,
  "ignore_paths": ["tests/", "node_modules/", ".git/"],
  "patterns": [
    {
      "name": "AWS Access Key",
      "regex": "AKIA[0-9A-Z]{16}",
      "confidence": 90
    },
    {
      "name": "GitHub Token",
      "regex": "ghp_[A-Za-z0-9]{36}",
      "confidence": 95
    },
    {
      "name": "Stripe Secret Key",
      "regex": "sk_live_[0-9a-zA-Z]{24}",
      "confidence": 90
    },
    {
      "name": "Generic API Key",
      "regex": "[aA][pP][iI][_-]?[kK][eE][yY][\\s]*[=:][\\s]*['\"]?[A-Za-z0-9_\\-]{20,}",
      "confidence": 50
    }
  ]
}
```

After editing, reinstall the config:

```bash
sudo cp config/patterns.json /usr/local/share/GitSentry/patterns.json
```

---

## Scoring system

```
score = base_confidence       (from patterns.json)
      + 10  if context keyword found (key, token, secret, password)
      - 20  if test/dummy keyword found (test, example, dummy, fake)
      + 15  if Shannon entropy >= 4.5

score >= 65  →  reported
score >= 90  →  immediate block, stops checking other patterns
score <  50  →  silently ignored
```

---

## Running the tests

```bash
cd GitSentry

g++ -std=c++17 -Ithird_party \
    tests/test_scanner.cpp \
    src/entropy.cpp \
    src/utils.cpp \
    -o test_runner

./test_runner
```

Expected output:

```
========================# GitSentry

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

=====
 GitSentry Unit Test Suite
=============================

[Entropy]
  PASS  AWS key has high entropy
  PASS  GitHub token has high entropy
  PASS  Repeated chars have low entropy
  PASS  Plain English word has low entropy
  PASS  Random alphanumeric string has high entropy
  PASS  Empty string returns 0 entropy

[AlphanumericHeavy]
  PASS  Long alphanumeric string is heavy
  PASS  Short string is not heavy
  PASS  Symbol-heavy string is not heavy
  PASS  Exactly 16 alphanumeric chars passes

[Masking]
  PASS  Long secret is masked correctly
  PASS  Short secret returns ****
  PASS  8-char secret returns ****
  PASS  9-char secret is masked
  PASS  Stripe key is masked correctly

[SplitLines]
  PASS  Splits 3 lines correctly
  PASS  First line is correct
  PASS  Last line is correct
  PASS  Single line with no newline
  PASS  Empty string gives empty vector

[PathIgnore]
  PASS  node_modules path is ignored
  PASS  tests path is ignored
  PASS  .git path is ignored
  PASS  src path is NOT ignored
  PASS  Empty path with no match

[RealWorldPatterns]
  PASS  AWS key has high entropy (>4.0)
  PASS  AWS key is alphanumeric heavy
  PASS  GitHub token has high entropy
  PASS  GitHub token is alphanumeric heavy
  PASS  Dummy key has lower entropy than real key

=============================
 Results: 26 passed, 0 failed
=============================
```

---

## Example output

**When a secret is detected:**
```
[GitSentry] BLOCKED — potential secrets detected:

  src/config.cpp
    Line 12  [AWS Access Key]  score=115
    AKIA****LE

[GitSentry] Commit blocked. Fix the above before committing.
```

**When everything is clean:**
```
[GitSentry] No secrets detected. Safe to commit.
```

---

## Uninstalling

```bash
# Remove hooks from current repo
GitSentry uninstall

# Remove the binary and config globally
sudo make uninstall
```

---

## Roadmap

- [x] Phase 1 — CLI & Git hook integration
- [x] Phase 2 — Regex + entropy detection engine
- [x] Phase 3 — Multithreaded parallel scanning
- [x] Phase 4 — Scoring system, false positive filtering, tests
- [ ] Phase 5 — GitHub Actions / CI integration
- [ ] Phase 6 — AI-based detection
- [ ] Phase 7 — Dashboard UI

---

## Security principles

- Secrets are never stored or transmitted
- Output always masks detected values: `AKIA****LE`
- Runs completely offline
- `.git/` internals and binary files are always skipped

---

*Built with C++17. No runtime dependencies.*