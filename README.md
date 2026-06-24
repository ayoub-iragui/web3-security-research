# Web3 Security Research

Educational security research by **Ayoub Aragui (aragui99)**.

Each writeup is an abstracted, vendor-genericized reproduction of a real-world
vulnerability. The math and architectural flaws remain 1:1 with the originals.

## Writeups

| Severity | Title | Category | Language |
|----------|-------|----------|----------|
| CRITICAL | [DRBG State Leakage in Threshold ECDSA](Cryptographic-Flaws/DRBG_State_Leakage.md) | Cryptographic Invariant Breach | C/C++ |
| CRITICAL | [Asymmetric Signature Validation (Infinite Reserve Minting)](Core-Infrastructure/Asymmetric_State_Minting.md) | State Deviation | C/C++ |
| CRITICAL | [Isolated Collateral Exhaustion (Global Debt Erasure)](DeFi-Logic-Flaws/Triple_Asset_Debt_Wipeout.md) | Economic Invariant Breach | Rust (Soroban) |

## Repository Structure

```
.
├── Cryptographic-Flaws/     # Cryptographic invariant breaches
├── Core-Infrastructure/     # DLT / state-machine level flaws
├── DeFi-Logic-Flaws/        # DeFi economic & logic exploits
├── shared/
│   ├── cpp/
│   │   ├── audit_log.h      # Logging & assertion macros (C/C++)
│   │   └── test_harness.h   # Base PoC test class (C/C++)
│   └── rust/
│       └── src/
│           ├── lib.rs
│           └── audit_log.rs  # Logging & assertion macros (Rust)
└── templates/
    └── WRITEUP_TEMPLATE.md   # Template for new writeups
```

## Shared Utilities

All PoC code uses shared logging and assertion helpers so that output is
consistent across writeups and languages.

### C/C++

```cpp
#include "shared/cpp/audit_log.h"    // AUDIT_INFO, AUDIT_CRITICAL, AUDIT_ASSERT, AUDIT_ASSERT_EQ
#include "shared/cpp/test_harness.h" // audit::test_harness base class
```

### Rust

```rust
#[macro_use] extern crate shared;    // audit_info!, audit_critical!, audit_assert!, audit_assert_eq!
```

## Adding a New Writeup

1. Copy `templates/WRITEUP_TEMPLATE.md` into the appropriate category directory.
2. Use the shared logging macros in your PoC code.
3. Add a row to the table above.
