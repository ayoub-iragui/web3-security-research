#pragma once
// audit_log.h - Shared logging and assertion macros for C/C++ PoC harnesses.
//
// Usage:
//   #include "shared/cpp/audit_log.h"
//
//   AUDIT_INFO("Init Quota", env.quota());
//   AUDIT_CRITICAL("Final Quota (MINTED)", final_q);
//   AUDIT_SEPARATOR();
//   AUDIT_ASSERT(final_q == 2, "quota should be minted from thin air");

#include <iostream>
#include <sstream>
#include <string>
#include <cstdlib>

#ifndef AUDIT_AUTHOR
#define AUDIT_AUTHOR "aragui99"
#endif

// --- Logging ----------------------------------------------------------

#define AUDIT_INFO(label, value) \
    do { \
        std::cout << "[*] " AUDIT_AUTHOR " - " << (label) << ": " << (value) << "\n"; \
    } while (0)

#define AUDIT_CRITICAL(label, value) \
    do { \
        std::cout << "[!] " AUDIT_AUTHOR " - " << (label) << ": " << (value) << "\n"; \
    } while (0)

#define AUDIT_MSG(msg) \
    do { \
        std::cout << "[*] " AUDIT_AUTHOR " - " << (msg) << "\n"; \
    } while (0)

#define AUDIT_SEPARATOR() \
    do { std::cout << "\n"; } while (0)

// --- Assertions -------------------------------------------------------

#define AUDIT_ASSERT(cond, description)                                     \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::cerr << "[FAIL] " AUDIT_AUTHOR " - Assertion failed: "     \
                      << (description) << "\n"                              \
                      << "       Expression: " #cond "\n"                   \
                      << "       " << __FILE__ << ":" << __LINE__ << "\n";  \
            std::abort();                                                   \
        }                                                                   \
        std::cout << "[PASS] " AUDIT_AUTHOR " - " << (description) << "\n";\
    } while (0)

#define AUDIT_ASSERT_EQ(actual, expected, description)                      \
    do {                                                                    \
        auto _a = (actual); auto _e = (expected);                           \
        if (_a != _e) {                                                     \
            std::cerr << "[FAIL] " AUDIT_AUTHOR " - " << (description)      \
                      << " | got " << _a << ", expected " << _e << "\n"     \
                      << "       " << __FILE__ << ":" << __LINE__ << "\n";  \
            std::abort();                                                   \
        }                                                                   \
        std::cout << "[PASS] " AUDIT_AUTHOR " - " << (description) << "\n";\
    } while (0)
