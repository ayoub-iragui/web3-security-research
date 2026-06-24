# [SEVERITY] Title of the Vulnerability

> **Disclosure:** Educational abstraction. Vendor details are genericized. Core flaw remains 1:1.

| Field      | Value                          |
|------------|--------------------------------|
| **Author** | Ayoub Aragui (aragui99)        |
| **Category** | _e.g. State Deviation, Economic Invariant Breach, Cryptographic Invariant Breach_ |
| **Language** | _e.g. C/C++, Rust (Soroban), Solidity_ |

---

## Context & Invariant

_Describe the protocol mechanism under test and state the security invariant
that must hold._

**Invariant:** _One-sentence formal statement of the property that is violated._

---

## The Flaw

_Explain the root cause — the structural or logical gap that breaks the
invariant. Include the relevant math / pseudocode if applicable._

---

## The Exploit

_Step-by-step attack flow:_

1. Step one
2. Step two
3. ...

**Impact:** _Quantify the damage (e.g. "100% loss of funds", "full key
compromise")._

---

## PoC

> Uses shared utilities from `shared/` — see `shared/cpp/audit_log.h`,
> `shared/cpp/test_harness.h` (C/C++) or `shared/rust/src/audit_log.rs` (Rust).

```<language>
// Paste PoC code here.
// Use AUDIT_INFO / AUDIT_CRITICAL / AUDIT_ASSERT (C++)
// or  audit_info! / audit_critical! / audit_assert! (Rust)
```

---

## Output

```
Paste expected console output here.
```
