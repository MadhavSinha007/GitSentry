CXX      = g++
CXXFLAGS = -std=c++17 -O2 -pthread -Wall -Wextra -Ithird_party
TARGET   = GitSentry
SRCS     = $(wildcard src/*.cpp)

PREFIX   ?= /usr/local
SHAREDIR = $(PREFIX)/share/GitSentry

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^

install: $(TARGET)
	@echo "[GitSentry] Installing binary..."
	sudo cp $(TARGET) $(PREFIX)/bin/

	@echo "[GitSentry] Installing config..."
	sudo mkdir -p $(SHAREDIR)
	sudo cp config/patterns.json $(SHAREDIR)/

	@echo "[GitSentry] Installing hooks..."
	sudo $(PREFIX)/bin/GitSentry install

clean:
	rm -f $(TARGET)

.PHONY: install clean