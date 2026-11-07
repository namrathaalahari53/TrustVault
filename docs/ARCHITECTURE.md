# TrustVault Architecture (docs/ARCHITECTURE.md)

TrustVault is structured around a strict defense-in-depth architecture where authorization decisions are computed server-side on every individual request.

---

## High-Level Architecture Diagram

```
+------------------------------------------------------------------------+
|                     Client Tier (React 19 SPA)                         |
|   - Zero-Trust UI Controls (visual affordance, not authorization)      |
|   - Bearer Authentication Interceptor & Token Rotation                 |
|   - In-App Automated Security Test Runner (30/30 Cases)                |
+------------------------------------+-----------------------------------+
                                     |
                                     | HTTPS / JSON / Streaming
                                     v
+------------------------------------+-----------------------------------+
|               API Gateway Tier (FastAPI & Express)                     |
|   - Rate Limiter (5 attempts / 300s lockout)                           |
|   - Request Correlation ID Injection (`req_uuid`)                      |
|   - Bearer Token & Session Validation                                  |
|   - Magic-Byte & Path Traversal Sanitizer                              |
+------------------------------------+-----------------------------------+
                                     |
                   +-----------------+-----------------+
                   |                                   |
                   v                                   v
+------------------+----------------+ +----------------+-----------------+
|     Authorization Enforcement     | |    Cryptographic Audit Engine   |
| - `require_document_read_access`  | | - SHA-256 Hash Chaining          |
| - `require_document_edit_access`  | | - Deterministic Canonical String |
| - `require_document_owner`        | | - Genesis Hash Linking           |
| - Immediate Revocation Guard      | | - Chain Verification Service     |
+------------------+----------------+ +----------------+-----------------+
                   |                                   |
                   v                                   v
+------------------+----------------+ +----------------+-----------------+
|     Encrypted Document Storage    | |     Relational Database Tier     |
| - Stored outside static roots     | | - Users, Documents, Permissions  |
| - Randomized UUID storage names   | | - AuditEvents, SecurityEvents    |
| - Streams directly to authorized  | | - Acid Transactions on Revoke    |
+-----------------------------------+ +----------------------------------+
```

---

## 1. Zero-Trust Access Lifecycle

1. **Authentication**: Users submit email and password. Password hash is verified using salted Argon2 / PBKDF2-SHA512 with timing-safe comparison. A short-lived (120 min) signed bearer token is issued.
2. **Access Delegation**: Document owners can grant `READ` or `EDIT` permissions to existing active accounts.
3. **Immediate Revocation**:
   - When an owner revokes access, the permission record is stamped with `revoked_at = NOW()` inside a database transaction.
   - Any open session holding a previously valid token that attempts to access the document will immediately evaluate `checkDocumentReadAccess()` against the database.
   - The query returns `NO_ACTIVE_READ_PERMISSION`, rejects the request with HTTP `403 Forbidden`, and emits an `UNAUTHORIZED_ACCESS_ATTEMPT` audit event.
   - No cached permissions or permanent static URLs are ever used.

---

## 2. Cryptographic Audit Hash Chaining

Audit integrity uses sequential block-like hash chaining:

$$\text{Genesis Hash} = 0^{64} = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$$

For each event $i$:
1. A canonical string is generated with sorted JSON metadata:
   $$\text{canonical\_str}_i = \text{seq} \parallel \text{actor\_id} \parallel \text{actor\_email} \parallel \text{action} \parallel \text{doc\_id} \parallel \text{target\_id} \parallel \text{ts} \parallel \text{outcome} \parallel \text{reason} \parallel \text{sorted\_meta}$$
2. The canonical payload hash is computed:
   $$\text{canonical\_hash}_i = \text{SHA256}(\text{canonical\_str}_i)$$
3. The event hash is linked to the previous event:
   $$\text{event\_hash}_i = \text{SHA256}(\text{previous\_hash}_i \parallel \text{canonical\_hash}_i)$$
4. The administrator verification endpoint loops through all events, recalculating every step from the genesis block. If any single character was altered in database storage, the link breaks and the anomaly is flagged.
