#!/bin/bash
set -e

command -v g++ >/dev/null 2>&1 || { echo "g++ required"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git required"; exit 1; }

echo "[GitSentry] Compiling..."
g++ -std=c++17 -O2 -pthread -Ithird_party src/*.cpp -o GitSentry

echo "[GitSentry] Installing binary..."
sudo mv GitSentry /usr/local/bin/GitSentry

echo "[GitSentry] Installing config..."
sudo mkdir -p /usr/local/share/GitSentry
sudo cp config/patterns.json /usr/local/share/GitSentry/

echo "[GitSentry] Installing hooks in current repo..."
GitSentry install

echo "[GitSentry] Done! Run: GitSentry scan"