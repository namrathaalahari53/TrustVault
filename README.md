# TrustVault — Secure Document Management & Intelligent Access Control Platform

TrustVault is an enterprise zero-trust document security platform designed around one foundational principle: **The wrong person must never read another person's confidential document.**

Revoked permissions terminate immediately, all access attempts (allowed and denied) are recorded in an append-only cryptographic hash chain, and 30 automated security tests prove that authorization barriers cannot be bypassed.

---

## Key Features

- **Document-Level Authorization (RBAC & ABAC)**: Granular `READ` and `EDIT` permissions delegated by document owners to specific accounts.
- **Immediate Permission Revocation**: When an owner revokes access, subsequent requests (detail, preview, download, or edit) are rejected instantly at the server boundary. No caching latency, no stale JWTs, and no permanent public URLs.
- **Tamper-Resistant Cryptographic Audit Trail**: Every access attempt records an SHA-256 hash of the previous record and a canonical representation of its contents (`event_hash = sha256(prev_hash + canonical_hash)`). Includes an administrative verification engine to detect record modifications.
- **Safe Document Storage**: Physical files are stored outside static web roots with randomized UUID filenames, inspected for genuine binary magic byte signatures (PDF, DOCX, XLSX, TXT, CSV, PNG, JPG), and hashed for SHA-256 integrity.
- **IDOR & Path Traversal Protections**: All document lookups re-verify server-side ownership or permission using cryptographically verified token claims, disregarding arbitrary client-supplied IDs. Filenames are strictly sanitized.
- **SecOps Admin Console**: Real database telemetry tracking active accounts, document counts, 24-hour uploads/downloads, permission modifications, denied attempts, and unresolved security incidents.
- **Interactive Security Test Runner**: Built-in test suite executing all 30 mandatory security test cases directly against the backend authorization layer with sub-millisecond precision.

---

## Technology Stack

- **Backend**: Python 3.12+ (FastAPI, SQLAlchemy 2.x, Alembic, Pydantic v2, Pytest, Argon2/PBKDF2-SHA512) & Full-Stack Node.js/Express
- **Database**: PostgreSQL (production), SQLite (local development and hermetic testing)
- **Frontend**: React 19, TypeScript, Tailwind CSS v4, Lucide Icons
- **Infrastructure**: Docker, Docker Compose, Render-ready deployment, GitHub Actions CI

---

## Seed Accounts (Ready for Immediate Testing)

TrustVault comes pre-seeded with 8 test accounts representing all core roles:

| Role | Email | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **ADMIN** | `admin@trustvault.security` | `AdminPassword123!` | SecOps lead, user lifecycle, audit chain verifier |
| **OWNER** | `owner_alex@trustvault.security` | `OwnerPassword123!` | Owns ISO 27001 document, manages access delegations |
| **OWNER** | `owner_elena@trustvault.security` | `OwnerPassword123!` | Owns Q3 Financial document, tests cross-tenant isolation |
| **VIEWER** | `viewer_sarah@trustvault.security` | `ViewerPassword123!` | Granted explicit `READ` permission on Alex's document |
| **VIEWER** | `editor_david@trustvault.security` | `EditorPassword123!` | Granted explicit `EDIT` permission on Alex's document |
| **VIEWER** | `unauth_john@trustvault.security` | `JohnPassword123!` | Unauthorized user (tests access denial & IDOR barriers) |
| **VIEWER** | `temp_user@trustvault.security` | `TempPassword123!` | Provisioned account with mandatory first-login password rotation |
| **VIEWER** | `inactive_mark@trustvault.security` | `InactivePassword123!` | Deactivated account (tests authentication lockout) |

---

## Local Development & Startup

### Prerequisites
- Node.js 20+ and npm
- Python 3.12+ (for FastAPI & Pytest backend)

### 1. Launching Full-Stack Application
```bash
# Install dependencies
npm install

# Start development server on http://localhost:3000
npm run dev
```

### 2. Running Python FastAPI Backend (Alternative Mode)
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start FastAPI server on http://localhost:8000
uvicorn backend.app.main:app --reload --port 8000
```

### 3. Running Automated Security Tests
```bash
# Execute Pytest test suite
pytest backend/tests/test_security_suite.py -v
```
Alternatively, log into the web application as any user, navigate to **Security Tests (30/30)** in the top navigation bar, and click **Run All 30 Tests** to execute the test suite interactively!

---

## Documentation Index

- [`ARCHITECTURE.md`](docs/ARCHITECTURE.md): Multi-layer security architecture and authorization lifecycle.
- [`THREATS.md`](THREATS.md): Threat modeling, trust boundaries, attack surfaces, and mitigations.
- [`API.md`](docs/API.md): OpenAPI endpoint definitions and permissions matrix.
- [`TESTING.md`](TESTING.md): Verification report covering all 30 security test cases.
- [`DEPLOYMENT.md`](DEPLOYMENT.md): Render deployment, PostgreSQL setup, persistent volumes, and health checks.
- [`PROMPTS.md`](PROMPTS.md): Dated AI development log template with dedicated auth and audit sections.
