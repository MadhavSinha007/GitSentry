CXX      = g++
CXXFLAGS = -std=c++17 -O2 -pthread -Wall -Wextra -Ithird_party
TARGET   = GitSentry
SRCS     = $(wildcard src/*.cpp)

PREFIX   ?= /usr/local
BINDIR    = $(PREFIX)/bin
SHAREDIR  = $(PREFIX)/share/GitSentry

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^

install: $(TARGET)
	@echo "[GitSentry] Installing binary to $(BINDIR)..."
	sudo cp $(TARGET) $(BINDIR)/

	@echo "[GitSentry] Installing config to $(SHAREDIR)..."
	sudo mkdir -p $(SHAREDIR)
	sudo cp config/patterns.json $(SHAREDIR)/patterns.json

	@echo "[GitSentry] Done. Run 'GitSentry install' inside any git repo."

uninstall:
	@echo "[GitSentry] Removing binary..."
	sudo rm -f $(BINDIR)/$(TARGET)
	@echo "[GitSentry] Removing config..."
	sudo rm -rf $(SHAREDIR)
	@echo "[GitSentry] Uninstalled."

clean:
	rm -f $(TARGET)

.PHONY: install uninstall clean