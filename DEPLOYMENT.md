# TrustVault Production Deployment Guide (DEPLOYMENT.md)

This guide details the deployment of TrustVault on Render (or any Docker/Kubernetes container cloud) with PostgreSQL and persistent document storage.

---

## 1. Render Deployment Architecture

TrustVault is deployed as:
1. **PostgreSQL Database**: Managed relational database service.
2. **Web Service (FastAPI / Express)**: Containerized web service running the security gateway.
3. **Persistent Disk (Render Disks)**: Mounted at `/app/storage/documents` to guarantee persistent document retention across restarts and deploys.

---

## 2. Environment Variables Configuration

Configure the following variables in the Render Dashboard (or production `.env` file):

| Variable | Description | Production Example |
| :--- | :--- | :--- |
| `NODE_ENV` | Application runtime environment | `production` |
| `PORT` | Listening network port | `3000` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://trustvault_user:SECRET@dpg-xyz.render.com/trustvault_prod` |
| `JWT_SECRET` | 256-bit secret key for signed tokens | `prod-sec-key-generate-random-high-entropy-64chars` |
| `STORAGE_DIR` | Absolute path to persistent storage disk | `/app/storage/documents` |
| `MAX_FILE_SIZE_MB` | Maximum allowed file upload size | `50` |
| `CORS_ORIGINS` | Permitted cross-origin origins | `https://trustvault.yourcompany.com` |

---

## 3. Database Migrations

Run database migrations before activating the service:

```bash
# Using Alembic (Python backend)
alembic upgrade head
```

---

## 4. Health & Readiness Probes

TrustVault exposes two dedicated endpoints for container orchestration:

### Liveness Probe (`/health`)
- **URL**: `GET /health`
- **Expected Status**: `200 OK`
- **Response**:
  ```json
  {
    "status": "healthy",
    "timestamp": "2026-11-06T12:00:00Z",
    "service": "trustvault-core",
    "version": "1.0.0"
  }
  ```

### Readiness Probe (`/ready`)
- **URL**: `GET /ready`
- **Checks**:
  - Persistent document storage volume is mounted and writable.
  - Database connection pool is active and responding.
  - Cryptographic audit hash chain is valid.
- **Expected Status**: `200 OK` (or `503 Service Unavailable` if dependencies fail).
- **Response**:
  ```json
  {
    "status": "ready",
    "storage_connected": true,
    "database_ready": true,
    "cryptographic_audit_chain_valid": true,
    "timestamp": "2026-11-06T12:00:00Z"
  }
  ```

---

## 5. Persistent Storage Configuration

Under **Render Dashboard > Web Service > Disks**:
- **Name**: `trustvault-document-volume`
- **Mount Path**: `/app/storage/documents`
- **Size**: `10 GB` (or as required)

> **CRITICAL**: Never use ephemeral container storage for confidential production documents. A persistent disk ensures documents survive container reboots and rolling updates.
