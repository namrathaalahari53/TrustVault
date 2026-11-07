# TrustVault Automated Security Testing Report (TESTING.md)

TrustVault integrates a comprehensive automated security verification suite executing against the real backend authorization layer. No mocked authorization decisions are used.

---

## Test Execution Commands

### 1. In-App Interactive Test Runner
Navigate to **Security Tests (30/30)** in the application navigation header and click **Run All 30 Tests**. The interactive runner executes all 30 tests in sub-millisecond cycles directly against the running authorization engine.

### 2. Python CLI Execution (Pytest)
```bash
pytest backend/tests/test_security_suite.py -v
```

---

## Automated Security Test Matrix (30 / 30 Cases)

| # | Test Name | Category | Expected Result | Actual Result | Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| 1 | Valid login succeeds | AUTHENTICATION | Generates bearer token | Token issued; Argon2 verified | **PASS** |
| 2 | Invalid password fails | AUTHENTICATION | Constant-time rejection | Rejected with 401 Unauthorized | **PASS** |
| 3 | Inactive account cannot authenticate | AUTHENTICATION | Blocked for deactivated user | `is_active: false` blocked with 403 | **PASS** |
| 4 | Owner can upload document | AUTHORIZATION | Stored with UUID and checksum | Written to secure storage with SHA-256 | **PASS** |
| 5 | Owner can read their document | AUTHORIZATION | Read access allowed | Owner identity matches `owner_id` | **PASS** |
| 6 | Viewer can read explicitly shared document | AUTHORIZATION | Active permission grants READ | Sarah permitted via `perm_sarah_doc1` | **PASS** |
| 7 | Viewer cannot edit | AUTHORIZATION | READ permission denies edit | Edit blocked (`NO_ACTIVE_EDIT_PERMISSION`) | **PASS** |
| 8 | Editor can edit shared document | AUTHORIZATION | EDIT permission allows edit | David authorized via active EDIT permission | **PASS** |
| 9 | Editor cannot delete owner's document | AUTHORIZATION | Non-owner delete blocked | Delete blocked (`NOT_DOCUMENT_OWNER`) | **PASS** |
| 10 | Unauthorized user cannot read | AUTHORIZATION | Unshared user denied access | John blocked with 403 Forbidden | **PASS** |
| 11 | Unauthorized user cannot download | AUTHORIZATION | Stream denied before opening | Download pre-check returned 403 | **PASS** |
| 12 | Unauthorized user cannot edit | AUTHORIZATION | Edit rejected by server guard | Update rejected with 403 Forbidden | **PASS** |
| 13 | Unauthorized user cannot delete | AUTHORIZATION | Delete rejected for non-owner | Delete rejected with 403 Forbidden | **PASS** |
| 14 | Changing document ID cannot bypass auth | IDOR_PROTECTION | Cross-document ID lookup re-verified | IDOR attempt rejected with 403 | **PASS** |
| 15 | Changing user ID cannot bypass auth | IDOR_PROTECTION | Server binds identity to verified token | Client payload user ID ignored | **PASS** |
| 16 | User A cannot access User B's private doc | AUTHORIZATION | Complete tenant isolation | Alex denied Elena's private document | **PASS** |
| 17 | Owner can grant READ access | AUTHORIZATION | Permission row created and audited | Delegated access granted in database | **PASS** |
| 18 | Owner can grant EDIT access | AUTHORIZATION | Permission upgraded to EDIT | Permission level updated in database | **PASS** |
| 19 | Owner can revoke access | REVOCATION | `revoked_at` timestamp recorded | Revoked transactionally | **PASS** |
| 20 | Revoked access fails immediately | REVOCATION | Next request blocked with 403 | Subsequent access denied immediately | **PASS** |
| 21 | Previously obtained URLs cannot bypass revocation | REVOCATION | Protected stream validates per-request | Direct streaming endpoint validates live | **PASS** |
| 22 | Denied access attempts are audited | AUDIT_INTEGRITY | Logged with DENIED outcome | Recorded at sequence with reason code | **PASS** |
| 23 | Successful downloads are audited | AUDIT_INTEGRITY | Logged with actor and filename | `DOCUMENT_DOWNLOAD` logged | **PASS** |
| 24 | Permission changes are audited | AUDIT_INTEGRITY | Grants and revocations logged | Chained in immutable audit trail | **PASS** |
| 25 | Ordinary users cannot alter audit records | AUDIT_INTEGRITY | Append-only immutability | No mutation endpoints exposed | **PASS** |
| 26 | Invalid file types rejected | FILE_SECURITY | Executables (`.exe`, `.sh`) rejected | Magic bytes check failed & rejected | **PASS** |
| 27 | Oversized files rejected | FILE_SECURITY | Files > 50MB rejected | Rejected before storage allocation | **PASS** |
| 28 | Filename traversal attacks rejected | FILE_SECURITY | `../../` sequences stripped | Sanitized to safe basename | **PASS** |
| 29 | Unauthorized users cannot access audit admin | AUTHORIZATION | Non-admin denied audit verify | Sarah (VIEWER) denied 403 Forbidden | **PASS** |
| 30 | Audit hash-chain detects modified records | AUDIT_INTEGRITY | Cryptographic mismatch pinpointed | Tampered sequence identified immediately | **PASS** |

---

## Test Execution Summary

- **Total Test Cases**: 30
- **Passed**: 30 (100%)
- **Failed**: 0
- **Average Execution Duration**: ~24 ms total
- **Verdict**: PASS — All acceptance criteria addressed.
