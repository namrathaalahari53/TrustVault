# AI Development Log Template (PROMPTS.md)

This document provides a structured, dated log template for recording interactions with AI coding engines during the architecture, implementation, hardening, and verification of TrustVault.

---

## Entry 1: Core Architecture & Database Modeling
- **Date**: [YYYY-MM-DD - Fill in actual date]
- **Actual Prompt**:
  ```text
  [Insert exact user prompt used to scaffold database schema, users, documents, permissions, and audit log tables]
  ```
- **AI Output**:
  ```text
  [Insert summarized or raw AI output generated]
  ```
- **What Was Wrong**:
  - [Identify any architectural gaps, missing foreign key constraints, or naive permission assumptions]
- **What I Changed**:
  - [Document architectural corrections, added indexes, and transactional boundaries]
- **Actual Commit Link**:
  - [Insert commit hash or Git commit link, e.g., commit 4f8a12...]

---

## Entry 2: Authentication & Session Security
- **Date**: [YYYY-MM-DD - Fill in actual date]
- **Actual Prompt**:
  ```text
  [Insert exact prompt used for Argon2/PBKDF2 password hashing, short-lived tokens, and brute-force rate limiting]
  ```
- **AI Output**:
  ```text
  [Insert summarized or raw AI output generated]
  ```
- **What Was Wrong**:
  - [Identify any credential exposure risks, weak token expiration, or missing salt handling]
- **What I Changed**:
  - [Document enforcement of timing-safe equality checks, mandatory first-login password rotation, and HttpOnly cookies]
- **Actual Commit Link**:
  - [Insert commit hash or Git commit link]

---

## Entry 3: Document-Level Authorization & Immediate Revocation (Dedicated Section)
- **Date**: [YYYY-MM-DD - Fill in actual date]
- **Actual Prompt**:
  ```text
  [Insert exact prompt requesting strict server-side authorization checks: require_document_read_access, require_document_edit_access, require_document_owner, and immediate revocation guarantees]
  ```
- **AI Output**:
  ```text
  [Insert summarized or raw AI output generated]
  ```
- **What Was Wrong**:
  - [Describe any instances where the AI generated client-side-only checks, cached permissions, or issued permanent file URLs]
- **What I Changed**:
  - [Detail how authorization was moved strictly to backend streaming handlers, eliminating caching and enforcing per-request database validation]
- **Actual Commit Link**:
  - [Insert commit hash or Git commit link]

---

## Entry 4: Cryptographic Hash Chaining & Audit Integrity (Dedicated Section)
- **Date**: [YYYY-MM-DD - Fill in actual date]
- **Actual Prompt**:
  ```text
  [Insert exact prompt specifying append-only audit trail with SHA-256 hash chaining, canonical payload serialization, and integrity verification]
  ```
- **AI Output**:
  ```text
  [Insert summarized or raw AI output generated]
  ```
- **What Was Wrong**:
  - [Detail any non-deterministic JSON serialization issues, sequence ordering edge cases, or false claims of absolute immutability]
- **What I Changed**:
  - [Document the implementation of deterministic canonical string formatting, genesis hash linking, and verification exception reporting]
- **Actual Commit Link**:
  - [Insert commit hash or Git commit link]

---

## Entry 5: Automated Security Testing & Hardening (30 Test Cases)
- **Date**: [YYYY-MM-DD - Fill in actual date]
- **Actual Prompt**:
  ```text
  [Insert exact prompt requesting automated security test suite covering all 30 test cases: IDOR, revocation, magic bytes, and path traversal]
  ```
- **AI Output**:
  ```text
  [Insert summarized or raw AI output generated]
  ```
- **What Was Wrong**:
  - [Identify any mocked authorization decisions, false positives, or incomplete test coverage]
- **What I Changed**:
  - [Document how all 30 tests were wired to test real backend authorization guards without mocked bypasses]
- **Actual Commit Link**:
  - [Insert commit hash or Git commit link]
