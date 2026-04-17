CXX      = g++
CXXFLAGS = -std=c++17 -O2 -pthread -Wall -Wextra -MMD -MP \
           -Ithird_party \
           -Isrc/app \
           -Isrc/cli \
           -Isrc/scanner \
           -Isrc/core

TARGET   = GitSentry

# Recursively find all .cpp files
SRCS = $(shell find src -name '*.cpp')

# Object and dependency files
OBJS = $(SRCS:.cpp=.o)
DEPS = $(OBJS:.o=.d)

PREFIX   ?= /usr/local
BINDIR    = $(PREFIX)/bin
SHAREDIR  = $(PREFIX)/share/GitSentry

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

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

run-help: $(TARGET)
	./$(TARGET) help

test-push-hook: $(TARGET)
	@echo "#!/bin/sh" > .git/hooks/pre-push
	@echo "cat | ./$(TARGET) scan --push" >> .git/hooks/pre-push
	chmod +x .git/hooks/pre-push
	@echo "[GitSentry] Wrote .git/hooks/pre-push"

clean:
	rm -f $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)

.PHONY: all install uninstall clean run-help test-push-hook