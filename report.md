# Rektoff Lecture 8 Assignment

## Project: `account_4` Program (Solana Bootcamp)

**Date:** October 2025
**Auditor:** Han (GitHub: @username) ([X]())
**Scope:** Review of `account_4/programs/account_4/src/lib.rs`

---

### 📚 Table of Contents

1. [Introduction](#intro)
2. [Methodology](#methodology)
3. [Security Review Summary](#summary)
4. [Findings Details](#findings-details)
   * [High Severity](#high-severity)
        * [H-01 – Missing Ownership Validation in `withdraw_from_vault`](#h1)
   * [Medium Severity](#medium-severity)
   * [Low Severity](#low-severity)
   * [Informational / Gas Optimization](#informational--gas-optimization)
5. [Recommendations](#recommendations)

---

## 🧩 Summary

Brief summary of what you reviewed and any notable design observations.

Example:

> The `account_4` Solana program handles creation of collection authorities and user vaults using PDAs.
> The logic is generally sound but lacks ownership validation on withdrawals and has potential seed overlap for vault authorities.

---

## 🧰 Methodology

Explain how you performed the audit — helps demonstrate professionalism.

Example:

* Reviewed codebase manually for logic and access control vulnerabilities
* Focused on PDA derivations, signer checks, and instruction constraints
* Tested common attack vectors such as unauthorized withdrawals and reinitialization

---

## 🧨 Findings Overview

| ID   | Title                                                        | Severity          | Status       | Description                                               |
| ---- | ------------------------------------------------------------ | ----------------- | ------------ | --------------------------------------------------------- |
| F-01 | Missing ownership validation in `withdraw_from_vault`        | **High**          | Unresolved   | Any user can withdraw from another’s vault                |
| F-02 | PDA seed overlap between vault and authority                 | **Medium**        | Acknowledged | Conflicting seed combinations can derive the same address |
| F-03 | Unchecked `vault_name` length can cause serialization issues | **Low**           | Unresolved   | Long names may exceed max account size                    |
| F-04 | Lack of event emission for withdrawals/deposits              | **Informational** | —            | Improves traceability                                     |

---

## 🔎 Findings Details

### High Severity

#### <a id="h1">H-01 – Missing Ownership Validation in `withdraw_from_vault`</a>

**Severity:** High

**Context:** [account_4/src/lib.rs](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/c51909976951612ed95d429b6083072e396e3c1e/lecture_2/account_4/programs/account_4/src/lib.rs#L98-L122)

**Description:**
The `withdraw_from_vault` instruction does not verify that `ctx.accounts.user` is the same as `vault.user_id`.
This allows any signer to withdraw funds from another user’s vault, as long as they supply the correct PDA.

**Finding Description**

```rust
pub fn withdraw_from_vault(
    ctx: Context<WithdrawFromVault>,
    user_id: u64,
    vault_name: String,
    amount: u64,
) -> Result<()> {
    let vault = &mut ctx.accounts.user_vault;
    require!(vault.balance >= amount, ErrorCode::InsufficientBalance);
    vault.balance -= amount;
    Ok(())
}
```

**Impact:**
Unauthorized withdrawals can drain user balances.

**Proof of Concept**

<details>
<summary>Click here to expand
</details>

**Recommendation:**
Add a check ensuring the signer matches the vault owner:

```rust
require!(
    vault.user_id == user_id && ctx.accounts.user.key() == expected_owner_key,
    ErrorCode::Unauthorized
);
```

---

### Medium Severity

#### F-02 – PDA Collision Risk

... (describe your reasoning)

---

## 🧭 Recommendations

* Add ownership validation for sensitive functions
* Implement stricter PDA seed design to avoid collisions
* Consider emitting events for transparency
* Add unit tests for ownership enforcement

---

## ✅ Appendix

Optionally include your test scripts or environment setup here.

---

### 💡 Folder Layout Suggestion for Submission

You don’t need many files — just this:

```
/audit-report/
│
├── README.md  ← (Main report)
├── findings/  ← (Optional: one file per bug if you want)
│   ├── F-01-missing-ownership-validation.md
│   └── F-02-pda-collision.md
└── screenshots/ (optional)
```

---

Would you like me to help you **fill in this template** using your actual findings from `account_4` (like the missing ownership validation and PDA overlap)?
I can generate a ready-to-submit `README.md` version for you.
