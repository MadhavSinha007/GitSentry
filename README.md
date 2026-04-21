![CI](https://github.com/MadhavSinha007/GitSentry/actions/workflows/ci.yml/badge.svg)
![Version](https://img.shields.io/github/v/tag/MadhavSinha007/GitSentry)
![License](https://img.shields.io/github/license/MadhavSinha007/GitSentry)
![Stars](https://img.shields.io/github/stars/MadhavSinha007/GitSentry?style=social)

# GitSentry

Local-first secret detection for Git workflows.

GitSentry is a high-performance CLI tool written in C++ that prevents sensitive credentials from being committed or pushed to Git repositories.

It integrates directly into Git using hooks and runs completely offline — no telemetry, no uploads.

---

## Features

- Pre-commit scanning — scans staged changes before commit  
- Pre-push protection — scans full repository before push  
- High-performance C++ engine — fast, multithreaded  
- Smart detection — regex + entropy + context scoring  
- 100% offline — nothing leaves your machine  
- Configurable rules — customize detection via `patterns.json`  

---

## How It Works

Run:

```bash
GitSentry install