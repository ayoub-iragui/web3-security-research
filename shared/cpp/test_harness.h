#pragma once
// test_harness.h - Base class for C/C++ exploit PoC test suites.
//
// Provides a uniform run/report lifecycle so each writeup's PoC only
// needs to implement `execute()`.
//
// Usage:
//   class my_test : public audit::test_harness {
//   public:
//       my_test() : test_harness("Asymmetric Minting") {}
//   protected:
//       void execute() override { /* exploit steps */ }
//   };
//
//   int main() { return my_test().run(); }

#include "audit_log.h"
#include <string>
#include <chrono>
#include <iostream>

namespace audit {

class test_harness {
public:
    explicit test_harness(std::string name) : name_(std::move(name)) {}
    virtual ~test_harness() = default;

    int run() {
        std::cout << "=== " AUDIT_AUTHOR " PoC: " << name_ << " ===\n\n";
        auto t0 = std::chrono::steady_clock::now();

        execute();

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        std::cout << "\n=== Completed in " << elapsed.count() << " ms ===\n";
        return 0;
    }

protected:
    virtual void execute() = 0;
    const std::string& name() const { return name_; }

private:
    std::string name_;
};

} // namespace audit
