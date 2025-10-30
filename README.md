# 🔍 Rektoff Cohort 2 — Lecture 8 Assignment Audit

This repository contains my **security audit submission** for the Rektoff Cohort 2, Lecture 8 assignment.  
The task involves auditing the `account_4` Solana program, which manages user vaults for deposit and withdrawal functionality using the Anchor framework.

---

## 📄 Audit Report

**[View Full Audit Report](https://github.com/honghan-dev/rektoff-cohort-2-lecture-8-assignment/blob/master/report.md)**

The report includes:
- Overview and methodology
- Severity distribution and findings table  
- Detailed descriptions, impacts, and recommendations for each issue  
- Proof-of-concept examples for key vulnerabilities  

---

## 🧠 Summary

**Scope:**  
`programs/account_4/src/lib.rs`

**Findings:**  
- 🔴 2 High severity issues  
- 🟡 1 Low severity issue  
- 🔵 2 Informational findings  

**Main issues identified:**  
- Missing ownership validation in `withdraw_from_vault`  
- PDA collision causing user funds to be stuck  
- Missing overflow check in `deposit_to_vault`

---

## 👨‍💻 Author
**Han (@honghan-dev)**  
- GitHub: [honghan-dev](https://github.com/honghan-dev)  
- Twitter/X: [@4lifemen](https://x.com/4lifemen)

---

📘 _Part of the Rektoff Web3 Security Cohort — Lecture 8 Assignment_
