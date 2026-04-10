// tests/test_scanner.cpp
// Compile: g++ -std=c++17 -Ithird_party tests/test_scanner.cpp src/entropy.cpp src/utils.cpp -o test_runner
// Run:     ./test_runner

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "../src/entropy.h"
#include "../src/utils.h"

// ─────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────
int passed = 0;
int failed = 0;

#define TEST(name, expr) do { \
    if (expr) { \
        std::cout << "  PASS  " << name << "\n"; \
        ++passed; \
    } else { \
        std::cerr << "  FAIL  " << name << "\n"; \
        ++failed; \
    } \
} while(0)

// ─────────────────────────────────────────────
// 1. Entropy tests
// ─────────────────────────────────────────────
void testEntropy() {
    std::cout << "\n[Entropy]\n";

    // Real AWS-key-like string — high entropy
    TEST("AWS key has high entropy",
        shannonEntropy("AKIAIOSFODNN7EXAMPLE") > 4.0);

    // GitHub token pattern — high entropy
    TEST("GitHub token has high entropy",
        shannonEntropy("ghp_aBcDeFgHiJkLmNoPqRsTuV") > 4.0);

    // Repeated characters — very low entropy
    TEST("Repeated chars have low entropy",
        shannonEntropy("aaaaaaaaaaaaaaaa") < 1.0);

    // Human-readable word — low entropy
    TEST("Plain English word has low entropy",
        shannonEntropy("helloworld123456") < 3.5);

    // Random-looking string — high entropy
    TEST("Random alphanumeric string has high entropy",
        shannonEntropy("xK9#mP2$nQ7@wR4!") > 3.5);

    // Empty string — should return 0
    TEST("Empty string returns 0 entropy",
        shannonEntropy("") == 0.0);
}

// ─────────────────────────────────────────────
// 2. isAlphanumericHeavy tests
// ─────────────────────────────────────────────
void testAlphanumericHeavy() {
    std::cout << "\n[AlphanumericHeavy]\n";

    // Long alphanumeric string — should be heavy
    TEST("Long alphanumeric string is heavy",
        isAlphanumericHeavy("AKIAIOSFODNN7EXAMPLE123"));

    // Too short — should fail length check
    TEST("Short string is not heavy",
        !isAlphanumericHeavy("abc123"));

    // Mostly symbols — should fail ratio check
    TEST("Symbol-heavy string is not heavy",
        !isAlphanumericHeavy("!@#$%^&*!@#$%^&*"));

    // Exactly 16 chars, all alphanumeric — should pass
    TEST("Exactly 16 alphanumeric chars passes",
        isAlphanumericHeavy("AKIAIOSFODNN7EXA"));
}

// ─────────────────────────────────────────────
// 3. maskSecret tests
// ─────────────────────────────────────────────
void testMasking() {
    std::cout << "\n[Masking]\n";

    // Normal long secret
    TEST("Long secret is masked correctly",
        maskSecret("AKIAIOSFODNN7EXAMPLE") == "AKIA****MPLE");

    // Short secret — should return ****
    TEST("Short secret returns ****",
        maskSecret("abc") == "****");

    // Exactly 8 chars — boundary, should return ****
    TEST("8-char secret returns ****",
        maskSecret("abcd1234") == "****");

    // 9 chars — just above boundary
    TEST("9-char secret is masked",
        maskSecret("abcde1234") == "abcd****1234");

    // Stripe key pattern
    TEST("Stripe key is masked correctly",
        maskSecret("sk_live_abcdefghijklmnop") == "sk_l****mnop");
}

// ─────────────────────────────────────────────
// 4. splitLines tests
// ─────────────────────────────────────────────
void testSplitLines() {
    std::cout << "\n[SplitLines]\n";

    auto lines = splitLines("line1\nline2\nline3");
    TEST("Splits 3 lines correctly",
        lines.size() == 3);
    TEST("First line is correct",
        lines[0] == "line1");
    TEST("Last line is correct",
        lines[2] == "line3");

    auto single = splitLines("onlyone");
    TEST("Single line with no newline",
        single.size() == 1 && single[0] == "onlyone");

    auto empty = splitLines("");
    TEST("Empty string gives empty vector",
        empty.empty());
}

// ─────────────────────────────────────────────
// 5. pathMatchesIgnore tests
// ─────────────────────────────────────────────
void testPathIgnore() {
    std::cout << "\n[PathIgnore]\n";

    std::vector<std::string> ignores = {"node_modules/", "tests/", ".git/"};

    TEST("node_modules path is ignored",
        pathMatchesIgnore("./node_modules/index.js", ignores));

    TEST("tests path is ignored",
        pathMatchesIgnore("./tests/test_scanner.cpp", ignores));

    TEST(".git path is ignored",
        pathMatchesIgnore("./.git/config", ignores));

    TEST("src path is NOT ignored",
        !pathMatchesIgnore("./src/scanner.cpp", ignores));

    TEST("Empty path with no match",
        !pathMatchesIgnore("./main.cpp", ignores));
}

// ─────────────────────────────────────────────
// 6. Real-world secret pattern tests
// ─────────────────────────────────────────────
void testRealWorldPatterns() {
    std::cout << "\n[RealWorldPatterns]\n";

    // AWS key — starts with AKIA, 20 chars total
    std::string awsKey = "AKIAIOSFODNN7EXAMPLE";
    TEST("AWS key has high entropy (>4.0)",
        shannonEntropy(awsKey) > 4.0);
    TEST("AWS key is alphanumeric heavy",
        isAlphanumericHeavy(awsKey));

    // GitHub token — ghp_ prefix
    std::string ghToken = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ12";
    TEST("GitHub token has high entropy",
        shannonEntropy(ghToken) > 4.0);
    TEST("GitHub token is alphanumeric heavy",
        isAlphanumericHeavy(ghToken));

    // Dummy/example key — should have low entropy
    std::string dummyKey = "example_key_123_dummy_placeholder";
    TEST("Dummy key has lower entropy than real key",
        shannonEntropy(dummyKey) < shannonEntropy(awsKey));
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
int main() {
    std::cout << "=============================\n";
    std::cout << " GitSentry Unit Test Suite\n";
    std::cout << "=============================\n";

    testEntropy();
    testAlphanumericHeavy();
    testMasking();
    testSplitLines();
    testPathIgnore();
    testRealWorldPatterns();

    std::cout << "\n=============================\n";
    std::cout << " Results: "
              << passed << " passed, "
              << failed << " failed\n";
    std::cout << "=============================\n";

    return failed > 0 ? 1 : 0;
}