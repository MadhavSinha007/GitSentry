# Makefile
CXX      = g++
CXXFLAGS = -std=c++17 -O2 -pthread -Wall -Wextra -Ithird_party
TARGET   = GitSentry
SRCS     = $(wildcard src/*.cpp)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

clean:
	rm -f $(TARGET)

.PHONY: install clean