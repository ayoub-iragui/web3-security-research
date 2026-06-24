// audit_log.rs - Shared logging and assertion helpers for Rust/Soroban PoC harnesses.
//
//   use shared::audit_log::{audit_info, audit_critical, audit_assert_eq};
//
//   audit_info!("Init Debt", init_data.total_debt);
//   audit_critical!("Post-Liquidation Debt", final_data.total_debt);
//   audit_assert_eq!(final_data.total_debt, 0, "debt should be wiped");

/// Print an informational audit line: `[*] aragui99 - <label>: <value>`
#[macro_export]
macro_rules! audit_info {
    ($label:expr, $value:expr) => {
        std::println!("[*] aragui99 - {}: {}", $label, $value);
    };
}

/// Print a critical finding line: `[!] aragui99 - <label>: <value>`
#[macro_export]
macro_rules! audit_critical {
    ($label:expr, $value:expr) => {
        std::println!("[!] aragui99 - {}: {}", $label, $value);
    };
}

/// Print a plain audit message: `[*] aragui99 - <msg>`
#[macro_export]
macro_rules! audit_msg {
    ($msg:expr) => {
        std::println!("[*] aragui99 - {}", $msg);
    };
}

/// Assert equality with audit-formatted output on failure.
#[macro_export]
macro_rules! audit_assert_eq {
    ($actual:expr, $expected:expr, $description:expr) => {
        let a = $actual;
        let e = $expected;
        assert_eq!(
            a, e,
            "[FAIL] aragui99 - {} | got {}, expected {}",
            $description, a, e
        );
        std::println!("[PASS] aragui99 - {}", $description);
    };
}

/// Assert a boolean condition with audit-formatted output.
#[macro_export]
macro_rules! audit_assert {
    ($cond:expr, $description:expr) => {
        assert!($cond, "[FAIL] aragui99 - {}", $description);
        std::println!("[PASS] aragui99 - {}", $description);
    };
}
