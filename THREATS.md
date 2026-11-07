# TrustVault Threat Model & Security Posture (THREATS.md)

## 1. Key Assets

1. **Confidential Document Storage**: Physical binary files stored on disk.
2. **Access Delegation Ledger**: Document permissions mapping users to `READ` and `EDIT` rights.
3. **Cryptographic Audit Trail**: Chained sequence of system events and access attempts.
4. **Authentication Credentials**: User password hashes (Argon2 / PBKDF2-SHA512) and bearer session tokens.
5. **System Identity & Roles**: Administrative authority and user active states.

---

## 2. Trust Boundaries

- **Client Boundary**: Web browser running React SPA is completely untrusted. All input parameters, user IDs, role assertions, and requested document IDs are validated server-side.
- **Gateway / API Boundary**: Express / FastAPI endpoints act as the policy enforcement point (PEP). Requires cryptographic bearer token verification before executing any business logic.
- **Service Layer Boundary**: Document operations require passing through `require_document_read_access`, `require_document_edit_access`, or `require_document_owner`.
- **Storage Boundary**: Storage directory (`storage/documents`) is placed outside public static routes and restricted from direct web access.
- **Database Boundary**: Parameterized ORM queries prevent SQL injection; database transactions ensure immediate revocation.

---

## 3. Attack Surfaces

1. **Public Authentication Endpoint (`/api/auth/login`)**:
   - *Attack*: Credential stuffing, brute-force password guessing.
   - *Mitigation*: IP and email-based rate limiting (locks account for 300s after 5 failed attempts). Every failed attempt is audited. Constant-time comparison prevents timing attacks.
2. **Document Upload Endpoint (`/api/documents`)**:
   - *Attack*: File upload of malicious executables (`.exe`, `.sh`, `.php`), path traversal (`../../../etc/passwd`), polyglot files, zip bombs.
   - *Mitigation*: File extension whitelist, strict magic-byte / binary header verification, safe basename normalization stripping traversal sequences, random UUID storage names, 50MB hard limit.
3. **Document Download & Preview Endpoints (`/api/documents/:id/download`)**:
   - *Attack*: Insecure Direct Object Reference (IDOR) to access unshared confidential files by guessing IDs.
   - *Mitigation*: Live database verification of active permissions for the calling authenticated user before streaming.
4. **Permission Revocation Endpoint (`/api/documents/:id/permissions/:userId`)**:
   - *Attack*: Stale token or cached permissions allowing a user whose access was revoked to continue downloading files.
   - *Mitigation*: Every streaming request executes live permission queries (`revoked_at IS NULL`). Permanent public download URLs are never generated.

---

## 4. Threat Scenarios & Mitigations

### Threat Scenario A: IDOR Probe for Competitor Document
- **Threat Actor**: User A tries to download User B's private contract by guessing `doc_q3_financial_audit`.
- **System Action**: Gateway extracts caller ID from bearer token, loads document metadata, verifies `owner_id != user.id` and queries `document_permissions` for active record.
- **Outcome**: Returns `403 Forbidden`. The incident is recorded in `audit_events` with outcome `DENIED` and reason `INSUFFICIENT_DOCUMENT_READ_PERMISSION`, triggering an entry in `security_events`.

### Threat Scenario B: Permission Revocation Race Condition
- **Threat Actor**: Employee Sarah Chen is terminated or removed from a project; owner revokes access while Sarah has the page open.
- **System Action**: Owner executes `DELETE /api/documents/:id/permissions/:userId`. Database marks `revoked_at` timestamp in transaction.
- **Outcome**: Sarah's subsequent attempt to click "Download" or "Inspect" executes a live check, finds `revoked_at != null`, rejects with 403, and blocks the stream.

### Threat Scenario C: Audit Log Rewriting / Log Tampering
- **Threat Actor**: An attacker or rogue user attempts to modify an audit log entry to erase unauthorized access attempts.
- **System Action**: The audit table is strictly append-only. Each record computes:
  $$\text{canonical\_hash} = \text{SHA256}(\text{seq} \parallel \text{actor} \parallel \text{action} \parallel \text{doc} \parallel \text{ts} \parallel \text{outcome} \parallel \text{meta})$$
  $$\text{event\_hash} = \text{SHA256}(\text{previous\_hash} \parallel \text{canonical\_hash})$$
- **Outcome**: When the administrator invokes `/api/audit/verify`, the verification algorithm recalculates from the genesis hash. Any modified field immediately creates a cryptographic hash mismatch, pinpointing the exact sequence number that was modified.

---

## 5. Residual & Accepted Risks

1. **Database Superuser Tampering**:
   - *Risk*: A rogue system administrator with unrestricted direct PostgreSQL / SQLite disk access could theoretically modify an event and recalculate the entire subsequent hash chain.
   - *Mitigation*: In enterprise production, append-only records should be periodically mirrored to external WORM (Write Once, Read Many) storage or cloud ledger services (e.g. AWS QLDB or GCP Cloud Key Management with audit export).
2. **Screen Scraping by Authorized Viewers**:
   - *Risk*: A user who possesses genuine `READ` permission can take screenshots of their monitor while reading a confidential document.
   - *Accepted Risk*: Client-side hardware capture cannot be fully prevented by software without specialized DRM hardware enclaves; watermarking and detailed audit logging provide non-repudiation.
