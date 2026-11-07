# TrustVault API Reference & Permissions Matrix (API.md)

All endpoints require a valid short-lived bearer token in the `Authorization: Bearer <TOKEN>` header, or a secure HttpOnly session cookie, unless marked public.

---

## Permissions Matrix

| Endpoint | Method | Required Role | Required Doc Permission | Audited? |
| :--- | :---: | :---: | :---: | :---: |
| `/api/auth/register` | `POST` | Public (Unauthenticated) | None | Yes (`USER_REGISTERED` / `REGISTRATION_FAILED`) |
| `/api/auth/login` | `POST` | Public (Unauthenticated) | None | Yes (`LOGIN_SUCCESS` / `LOGIN_FAILURE`) |
| `/api/auth/logout` | `POST` | Authenticated | None | Yes (`LOGOUT`) |
| `/api/auth/me` | `GET` | Authenticated | None | No |
| `/api/auth/change-password` | `POST` | Authenticated | None | Yes (`PASSWORD_CHANGED`) |
| `/api/documents` | `GET` | Authenticated | Filtered to owned/shared | No (Index listing) |
| `/api/documents` | `POST` | Owner / Admin | None (Creator becomes Owner) | Yes (`DOCUMENT_UPLOAD`) |
| `/api/documents/:id` | `GET` | Authenticated | `READ`, `EDIT`, or `OWNER` | Yes (`DOCUMENT_READ`) |
| `/api/documents/:id/preview`| `GET` | Authenticated | `READ`, `EDIT`, or `OWNER` | Yes (`DOCUMENT_PREVIEW`) |
| `/api/documents/:id/download`| `GET` | Authenticated | `READ`, `EDIT`, or `OWNER` | Yes (`DOCUMENT_DOWNLOAD`) |
| `/api/documents/:id` | `PUT` | Authenticated | `EDIT` or `OWNER` | Yes (`DOCUMENT_EDIT`) |
| `/api/documents/:id` | `DELETE`| Authenticated | `OWNER` strictly | Yes (`DOCUMENT_DELETE`) |
| `/api/documents/:id/permissions`| `GET`| Owner / Admin | `OWNER` or Admin | Yes if unauthorized |
| `/api/documents/:id/permissions`| `POST`| Owner | `OWNER` strictly | Yes (`PERMISSION_GRANTED`) |
| `/api/documents/:id/permissions/:userId`| `DELETE`| Owner | `OWNER` strictly | Yes (`PERMISSION_REVOKED`) |
| `/api/audit/events` | `GET` | Authenticated | Admin sees all; User sees own | No |
| `/api/audit/verify` | `GET` | Admin strictly | `ADMIN` role | Yes (`AUDIT_INTEGRITY_CHECK`) |
| `/api/admin/metrics` | `GET` | Admin strictly | `ADMIN` role | No |
| `/api/admin/users` | `GET` / `POST` | Admin strictly | `ADMIN` role | Yes (`USER_CREATED`) |
| `/api/admin/users/:id` | `PATCH` | Admin strictly | `ADMIN` role | Yes (`USER_DEACTIVATED` / `ADMIN_SECURITY_ACTION`) |
| `/api/tests/run` | `POST` | Authenticated | None | Yes |

---

## Detailed Endpoint Specifications

### 1. Authentication

#### `POST /api/auth/login`
- **Purpose**: Authenticate user credentials and return signed short-lived bearer token.
- **Request Body**:
  ```json
  {
    "email": "owner_alex@trustvault.security",
    "password": "OwnerPassword123!"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "usr_owner_alex",
      "email": "owner_alex@trustvault.security",
      "role": "OWNER",
      "full_name": "Alex Rivera",
      "department": "Core Infrastructure",
      "must_change_password": false
    }
  }
  ```
- **Errors**: `400 Bad Request`, `401 Invalid Credentials`, `403 Account Inactive`, `429 Rate Limit Exceeded`.

---

### 2. Document Operations

#### `POST /api/documents`
- **Purpose**: Upload and encrypt a confidential file.
- **Content-Type**: `multipart/form-data`
- **Form Fields**: `file` (binary), `title` (string), `description` (string), `category` (string).
- **Enforcement**:
  - Validates magic bytes (PDF, DOCX, XLSX, TXT, CSV, PNG, JPG).
  - Maximum size: 50MB.
  - Sanitizes filename to remove path traversal sequences (`../`).
  - Stored outside public web root with random UUID filename.
- **Response `201 Created`**:
  ```json
  {
    "document": {
      "id": "doc_a1b2c3d4",
      "title": "SOC 2 Type II Report",
      "original_filename": "soc2_report.pdf",
      "mime_type": "application/pdf",
      "file_size": 204850,
      "sha256_checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "document_status": "ACTIVE",
      "created_at": "2026-11-06T12:00:00Z"
    }
  }
  ```

#### `GET /api/documents/:id/download`
- **Purpose**: Download permitted document.
- **Headers**: `Authorization: Bearer <TOKEN>`
- **Authorization Enforcement**:
  - Live check: `caller.id == doc.owner_id OR active_permission(doc.id, caller.id) IN ['READ', 'EDIT']`.
  - If access was revoked, returns `403 Forbidden` immediately.
- **Response**: Binary stream with headers:
  - `Content-Disposition: attachment; filename="<original_filename>"`
  - `X-Content-Type-Options: nosniff`
- **Errors**: `403 Access Denied`, `404 Document Not Found`.

---

### 3. Permissions & Immediate Revocation

#### `POST /api/documents/:id/permissions`
- **Purpose**: Grant `READ` or `EDIT` access to a named user.
- **Requirement**: Calling user must own the document.
- **Request Body**:
  ```json
  {
    "targetEmail": "viewer_sarah@trustvault.security",
    "permissionLevel": "READ"
  }
  ```
- **Response `201 Created`**:
  ```json
  {
    "permission": {
      "id": "perm_98765432",
      "document_id": "doc_a1b2c3d4",
      "user_email": "viewer_sarah@trustvault.security",
      "permission_level": "READ",
      "granted_at": "2026-11-06T12:05:00Z"
    }
  }
  ```

#### `DELETE /api/documents/:id/permissions/:userId`
- **Purpose**: Immediately revoke access for target user.
- **Requirement**: Calling user must own the document (or Admin).
- **Execution**: Updates `revoked_at = NOW()` transactionally in database.
- **Response `200 OK`**:
  ```json
  {
    "success": true,
    "message": "Permission revoked immediately. Subsequent access will be blocked."
  }
  ```

---

### 4. Audit & Cryptographic Chain

#### `GET /api/audit/verify`
- **Purpose**: Recalculate entire audit hash chain from genesis to head and pinpoint any modified record.
- **Requirement**: `ADMIN` role.
- **Response `200 OK`**:
  ```json
  {
    "is_valid": true,
    "total_events": 48,
    "verified_events": 48,
    "tampered_event_id": null,
    "tampered_sequence": null,
    "error_message": null,
    "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "latest_event_hash": "7a8f9c0e1b2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
    "chain_head_timestamp": "2026-11-06T12:15:30Z"
  }
  ```
