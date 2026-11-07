import os
import uuid
import hashlib
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.database.session import engine, get_db
from backend.app.models.models import (
    Base,
    User,
    Document,
    DocumentPermission,
    AuditEvent,
    SecurityEvent,
    UserRole,
    PermissionLevel,
    DocumentStatus,
    AuditOutcome,
)
from backend.app.schemas.schemas import (
    UserResponse,
    TokenResponse,
    LoginRequest,
    RegisterRequest,
    PasswordChangeRequest,
    DocumentResponse,
    DocumentUpdate,
    PermissionGrantRequest,
    PermissionResponse,
    AuditEventResponse,
    AuditVerificationResponse,
)
from backend.app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    validate_magic_bytes,
    sanitize_filename,
    check_login_rate_limit,
    record_login_attempt,
    security_bearer,
)
from backend.app.services.audit_service import AuditService
from jose import jwt, JWTError

app = FastAPI(
    title="TrustVault — Enterprise Secure Document Management & Access Control",
    version="1.0.0",
    description="""
# TrustVault Security API Specification
TrustVault enforces zero-trust document boundaries, immediate permission revocation, 
and cryptographically chained append-only audit verification.

### Permissions Matrix:
| Role / Actor | Read Own Docs | Read Shared Docs | Edit Shared Docs | Grant / Revoke Access | Delete Doc | Audit Console |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Owner** | Yes | Yes (if shared) | Yes (if EDIT) | Yes (own docs) | Yes (own docs) | Own docs only |
| **Editor** | Yes | Yes | Yes (if EDIT) | No | No | Own actions |
| **Viewer** | Yes | Yes (if READ) | No | No | No | Own actions |
| **Admin** | Yes (audited) | Metadata | Metadata | No (audited) | No (audited) | Full System |
    """,
    openapi_tags=[
        {"name": "Health", "description": "Liveness & readiness health probes"},
        {"name": "Auth", "description": "Authentication, token rotation, and password controls"},
        {"name": "Documents", "description": "Secure document storage, upload, preview, and download"},
        {"name": "Permissions", "description": "Granular delegation and immediate revocation"},
        {"name": "Audit", "description": "Append-only chained audit trail and cryptographic verification"},
        {"name": "Admin", "description": "Administrator metrics, user lifecycle, and security events"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup bootstrap
@app.on_event("startup")
def startup_event():
    os.makedirs(settings.STORAGE_DIR, exist_ok=True)
    Base.metadata.create_all(bind=engine)

    # Seed initial test users if empty
    from backend.app.database.session import SessionLocal
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            print("[TrustVault Python] Seeding accounts in database...")
            users = [
                User(
                    id="usr_admin_01",
                    email="admin@trustvault.security",
                    password_hash=hash_password("AdminPassword123!"),
                    role=UserRole.ADMIN,
                    full_name="Arthur Vance (SecOps Lead)",
                    department="Security Operations",
                    is_active=True,
                    must_change_password=False,
                ),
                User(
                    id="usr_owner_alex",
                    email="owner_alex@trustvault.security",
                    password_hash=hash_password("OwnerPassword123!"),
                    role=UserRole.OWNER,
                    full_name="Alex Rivera (Principal Architect)",
                    department="Core Infrastructure",
                    is_active=True,
                    must_change_password=False,
                ),
                User(
                    id="usr_viewer_sarah",
                    email="viewer_sarah@trustvault.security",
                    password_hash=hash_password("ViewerPassword123!"),
                    role=UserRole.VIEWER,
                    full_name="Sarah Chen (Security Auditor)",
                    department="Internal Audit",
                    is_active=True,
                    must_change_password=False,
                ),
                User(
                    id="usr_editor_david",
                    email="editor_david@trustvault.security",
                    password_hash=hash_password("EditorPassword123!"),
                    role=UserRole.VIEWER,
                    full_name="David Keller (DevSecOps)",
                    department="Security Engineering",
                    is_active=True,
                    must_change_password=False,
                ),
                User(
                    id="usr_unauth_john",
                    email="unauth_john@trustvault.security",
                    password_hash=hash_password("JohnPassword123!"),
                    role=UserRole.VIEWER,
                    full_name="John Miller (Junior Analyst)",
                    department="Operations",
                    is_active=True,
                    must_change_password=False,
                ),
                User(
                    id="usr_inactive_mark",
                    email="inactive_mark@trustvault.security",
                    password_hash=hash_password("InactivePassword123!"),
                    role=UserRole.VIEWER,
                    full_name="Mark Hansen (Deactivated)",
                    department="Vendor Risk",
                    is_active=False,
                    must_change_password=False,
                ),
            ]
            db.add_all(users)
            db.commit()

            # Seed doc1
            sample_content = b"TRUSTVAULT RESTRICTED SECURITY SPECIFICATION\nClassification: RESTRICTED\nOwner: Alex Rivera"
            storage_name = "doc_iso_27001_soc2.txt"
            with open(os.path.join(settings.STORAGE_DIR, storage_name), "wb") as f:
                f.write(sample_content)

            doc1 = Document(
                id="doc_iso_27001_soc2",
                title="ISO 27001 & SOC 2 Security Policy",
                description="Comprehensive access control specifications and zero-trust perimeter controls.",
                category="Compliance & Security",
                owner_id="usr_owner_alex",
                original_filename="ISO_27001_SOC2_Plan.txt",
                storage_path=storage_name,
                mime_type="text/plain",
                file_size=len(sample_content),
                sha256_checksum=hashlib.sha256(sample_content).hexdigest(),
                document_status=DocumentStatus.ACTIVE,
            )
            db.add(doc1)
            db.commit()

            # Seed Sarah READ, David EDIT
            p1 = DocumentPermission(
                id="perm_sarah_doc1",
                document_id="doc_iso_27001_soc2",
                user_id="usr_viewer_sarah",
                permission_level=PermissionLevel.READ,
                granted_by_user_id="usr_owner_alex",
            )
            p2 = DocumentPermission(
                id="perm_david_doc1",
                document_id="doc_iso_27001_soc2",
                user_id="usr_editor_david",
                permission_level=PermissionLevel.EDIT,
                granted_by_user_id="usr_owner_alex",
            )
            db.add_all([p1, p2])
            db.commit()

            AuditService.record_event(
                db=db,
                actor_user_id="usr_admin_01",
                actor_email="admin@trustvault.security",
                action="SYSTEM_GENESIS",
                document_id=None,
                target_user_id=None,
                outcome=AuditOutcome.SUCCESS,
                reason_code="SYSTEM_BOOTSTRAP",
                request_id="req_init_py",
            )
    finally:
        db.close()

# Dependency: Authenticated User
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security_bearer),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication token required.")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims.")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is deactivated.")
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required.")
    return current_user

# ==========================================
# HEALTH & READINESS ENDPOINTS
# ==========================================

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "trustvault-python-fastapi",
        "version": "1.0.0",
    }

@app.get("/ready", tags=["Health"])
def readiness_check(db: Session = Depends(get_db)):
    storage_ok = os.path.exists(settings.STORAGE_DIR)
    db_ok = db.query(User).first() is not None
    audit_ok = AuditService.verify_chain(db)["is_valid"]
    if storage_ok and db_ok and audit_ok:
        return {"status": "ready", "storage": True, "database": True, "audit_chain": True}
    return JSONResponse(
        status_code=503,
        content={"status": "not_ready", "storage": storage_ok, "database": db_ok, "audit_chain": audit_ok},
    )

# ==========================================
# AUTH ENDPOINTS
# ==========================================

@app.post("/api/auth/register", response_model=TokenResponse, status_code=201, tags=["Auth"])
def register_user(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    clean_email = req.email.lower().strip()
    existing = db.query(User).filter(User.email == clean_email).first()
    if existing:
        AuditService.record_event(
            db=db,
            actor_user_id=None,
            actor_email=clean_email,
            action="REGISTRATION_FAILED",
            document_id=None,
            target_user_id=None,
            outcome=AuditOutcome.DENIED,
            reason_code="EMAIL_ALREADY_REGISTERED",
            request_id=str(uuid.uuid4()),
        )
        raise HTTPException(status_code=409, detail="An account with this email address already exists.")

    safe_role = UserRole.OWNER if (req.role or "").upper() == "OWNER" else UserRole.VIEWER
    user = User(
        id=f"usr_{uuid.uuid4().hex[:8]}",
        email=clean_email,
        password_hash=hash_password(req.password),
        role=safe_role,
        full_name=req.full_name.strip(),
        department=(req.department or "General").strip(),
        is_active=True,
        must_change_password=False,
        last_login_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role.value})

    AuditService.record_event(
        db=db,
        actor_user_id=user.id,
        actor_email=user.email,
        action="USER_REGISTERED",
        document_id=None,
        target_user_id=user.id,
        outcome=AuditOutcome.SUCCESS,
        reason_code="SELF_SERVICE_REGISTRATION",
        request_id=str(uuid.uuid4()),
        metadata={"role": user.role.value, "department": user.department},
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )

@app.post("/api/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    rate_key = f"{req.email}_{client_ip}"
    if not check_login_rate_limit(rate_key):
        AuditService.record_event(
            db=db,
            actor_user_id=None,
            actor_email=req.email,
            action="LOGIN_FAILURE",
            document_id=None,
            target_user_id=None,
            outcome=AuditOutcome.DENIED,
            reason_code="RATE_LIMIT_EXCEEDED",
            request_id=str(uuid.uuid4()),
        )
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Temporarily locked.")

    user = db.query(User).filter(User.email == req.email.lower()).first()
    if not user or not verify_password(req.password, user.password_hash):
        record_login_attempt(rate_key, False)
        AuditService.record_event(
            db=db,
            actor_user_id=user.id if user else None,
            actor_email=req.email,
            action="LOGIN_FAILURE",
            document_id=None,
            target_user_id=None,
            outcome=AuditOutcome.DENIED,
            reason_code="INVALID_CREDENTIALS",
            request_id=str(uuid.uuid4()),
        )
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        AuditService.record_event(
            db=db,
            actor_user_id=user.id,
            actor_email=user.email,
            action="LOGIN_FAILURE",
            document_id=None,
            target_user_id=None,
            outcome=AuditOutcome.DENIED,
            reason_code="ACCOUNT_INACTIVE",
            request_id=str(uuid.uuid4()),
        )
        raise HTTPException(status_code=403, detail="Account is deactivated.")

    record_login_attempt(rate_key, True)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role.value})

    AuditService.record_event(
        db=db,
        actor_user_id=user.id,
        actor_email=user.email,
        action="LOGIN_SUCCESS",
        document_id=None,
        target_user_id=None,
        outcome=AuditOutcome.SUCCESS,
        reason_code="AUTHENTICATED",
        request_id=str(uuid.uuid4()),
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )

@app.get("/api/auth/me", response_model=UserResponse, tags=["Auth"])
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)

# ==========================================
# DOCUMENT ENDPOINTS
# ==========================================

@app.get("/api/documents", tags=["Documents"])
def list_documents(
    search: str = None,
    category: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Document).filter(Document.document_status != DocumentStatus.DELETED)
    all_docs = query.all()

    # Authorization filtering: owned or explicitly shared (or admin overview)
    accessible = []
    for doc in all_docs:
        if doc.owner_id == current_user.id or current_user.role == UserRole.ADMIN:
            accessible.append(doc)
        else:
            perm = db.query(DocumentPermission).filter(
                DocumentPermission.document_id == doc.id,
                DocumentPermission.user_id == current_user.id,
                DocumentPermission.revoked_at.is_(None),
            ).first()
            if perm:
                accessible.append(doc)

    # Filter by search
    if search:
        s = search.lower()
        accessible = [d for d in accessible if s in d.title.lower() or s in d.description.lower()]

    if category and category != "ALL":
        accessible = [d for d in accessible if d.category.lower() == category.lower()]

    results = []
    for d in accessible:
        is_owner = d.owner_id == current_user.id
        perm = None if is_owner else db.query(DocumentPermission).filter(
            DocumentPermission.document_id == d.id,
            DocumentPermission.user_id == current_user.id,
            DocumentPermission.revoked_at.is_(None),
        ).first()

        results.append({
            "id": d.id,
            "title": d.title,
            "description": d.description,
            "category": d.category,
            "owner_id": d.owner_id,
            "original_filename": d.original_filename,
            "mime_type": d.mime_type,
            "file_size": d.file_size,
            "sha256_checksum": d.sha256_checksum,
            "document_status": d.document_status.value,
            "created_at": d.created_at,
            "updated_at": d.updated_at,
            "is_owner": is_owner,
            "user_permission": "OWNER" if is_owner else (perm.permission_level.value if perm else ("METADATA_ONLY" if current_user.role == UserRole.ADMIN else "NONE")),
        })

    return {"documents": results, "total": len(results)}

@app.post("/api/documents", tags=["Documents"])
async def upload_document(
    title: str = Form(...),
    description: str = Form(""),
    category: str = Form("General"),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    safe_name = sanitize_filename(file.filename)
    _, ext = os.path.splitext(safe_name)
    content = await file.read()

    # Magic byte check
    valid, reason = validate_magic_bytes(content, ext)
    if not valid:
        AuditService.record_event(
            db=db,
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            action="INVALID_FILE_UPLOAD",
            document_id=None,
            target_user_id=None,
            outcome=AuditOutcome.DENIED,
            reason_code="MAGIC_BYTE_VALIDATION_FAILED",
            request_id=str(uuid.uuid4()),
            metadata={"filename": safe_name, "error": reason},
        )
        raise HTTPException(status_code=400, detail=reason)

    storage_id = f"tv_{uuid.uuid4().hex}{ext}"
    storage_path = os.path.join(settings.STORAGE_DIR, storage_id)
    with open(storage_path, "wb") as f:
        f.write(content)

    checksum = hashlib.sha256(content).hexdigest()
    doc = Document(
        id=f"doc_{uuid.uuid4().hex[:8]}",
        title=title,
        description=description,
        category=category,
        owner_id=current_user.id,
        original_filename=safe_name,
        storage_path=storage_id,
        mime_type=file.content_type or "application/octet-stream",
        file_size=len(content),
        sha256_checksum=checksum,
        document_status=DocumentStatus.ACTIVE,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    AuditService.record_event(
        db=db,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        action="DOCUMENT_UPLOAD",
        document_id=doc.id,
        target_user_id=None,
        outcome=AuditOutcome.SUCCESS,
        reason_code="DOCUMENT_STORED_SECURELY",
        request_id=str(uuid.uuid4()),
        metadata={"filename": safe_name, "size": len(content), "checksum": checksum},
    )

    return {"document": DocumentResponse.model_validate(doc)}

# Download Document (READ authorization strictly required)
@app.get("/api/documents/{document_id}/download", tags=["Documents"])
def download_document(
    document_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = db.query(Document).filter(Document.id == document_id, Document.document_status != DocumentStatus.DELETED).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    # Authorization
    has_read = False
    if doc.owner_id == current_user.id:
        has_read = True
    else:
        perm = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == doc.id,
            DocumentPermission.user_id == current_user.id,
            DocumentPermission.revoked_at.is_(None),
        ).first()
        if perm and perm.permission_level in [PermissionLevel.READ, PermissionLevel.EDIT]:
            has_read = True

    if not has_read:
        AuditService.record_event(
            db=db,
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            document_id=doc.id,
            target_user_id=None,
            outcome=AuditOutcome.DENIED,
            reason_code="DOWNLOAD_ACCESS_DENIED",
            request_id=str(uuid.uuid4()),
        )
        raise HTTPException(status_code=403, detail="Permission denied. You cannot download this document.")

    storage_path = os.path.join(settings.STORAGE_DIR, doc.storage_path)
    if not os.path.exists(storage_path):
        raise HTTPException(status_code=404, detail="Storage file not found.")

    AuditService.record_event(
        db=db,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        action="DOCUMENT_DOWNLOAD",
        document_id=doc.id,
        target_user_id=None,
        outcome=AuditOutcome.SUCCESS,
        reason_code="DOWNLOAD_AUTHORIZED",
        request_id=str(uuid.uuid4()),
        metadata={"filename": doc.original_filename, "size": doc.file_size},
    )

    def iterfile():
        with open(storage_path, "rb") as f:
            while chunk := f.read(65536):
                yield chunk

    return StreamingResponse(
        iterfile(),
        media_type=doc.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{doc.original_filename}"'},
    )

# Grant Permission (Owner only)
@app.post("/api/documents/{document_id}/permissions", tags=["Permissions"])
def grant_permission(
    document_id: str,
    req: PermissionGrantRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = db.query(Document).filter(Document.id == document_id, Document.document_status != DocumentStatus.DELETED).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    if doc.owner_id != current_user.id:
        AuditService.record_event(
            db=db,
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            document_id=doc.id,
            target_user_id=None,
            outcome=AuditOutcome.DENIED,
            reason_code="NON_OWNER_PERMISSION_GRANT_ATTEMPT",
            request_id=str(uuid.uuid4()),
        )
        raise HTTPException(status_code=403, detail="Only document owner can grant permissions.")

    target = db.query(User).filter(User.email == req.target_email.lower()).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found.")
    if not target.is_active:
        raise HTTPException(status_code=400, detail="Cannot grant permissions to inactive account.")

    # Find existing active or create new
    existing = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id,
        DocumentPermission.user_id == target.id,
        DocumentPermission.revoked_at.is_(None),
    ).first()

    if existing:
        existing.permission_level = PermissionLevel(req.permission_level)
        db.commit()
        db.refresh(existing)
        perm = existing
    else:
        perm = DocumentPermission(
            id=f"perm_{uuid.uuid4().hex[:8]}",
            document_id=doc.id,
            user_id=target.id,
            permission_level=PermissionLevel(req.permission_level),
            granted_by_user_id=current_user.id,
        )
        db.add(perm)
        db.commit()
        db.refresh(perm)

    AuditService.record_event(
        db=db,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        action="PERMISSION_GRANTED",
        document_id=doc.id,
        target_user_id=target.id,
        outcome=AuditOutcome.SUCCESS,
        reason_code="EXPLICIT_DELEGATION",
        request_id=str(uuid.uuid4()),
        metadata={"level": req.permission_level, "target_email": target.email},
    )

    return {"status": "success", "permission_id": perm.id}

# Revoke Permission (Owner only) - IMMEDIATE ENFORCEMENT
@app.delete("/api/documents/{document_id}/permissions/{target_user_id}", tags=["Permissions"])
def revoke_permission(
    document_id: str,
    target_user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = db.query(Document).filter(Document.id == document_id, Document.document_status != DocumentStatus.DELETED).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    if doc.owner_id != current_user.id and current_user.role != UserRole.ADMIN:
        AuditService.record_event(
            db=db,
            actor_user_id=current_user.id,
            actor_email=current_user.email,
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            document_id=doc.id,
            target_user_id=target_user_id,
            outcome=AuditOutcome.DENIED,
            reason_code="NON_OWNER_PERMISSION_REVOCATION_ATTEMPT",
            request_id=str(uuid.uuid4()),
        )
        raise HTTPException(status_code=403, detail="Only document owner can revoke permissions.")

    perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id,
        DocumentPermission.user_id == target_user_id,
        DocumentPermission.revoked_at.is_(None),
    ).first()

    if not perm:
        raise HTTPException(status_code=404, detail="No active permission found.")

    perm.revoked_at = datetime.now(timezone.utc)
    db.commit()

    AuditService.record_event(
        db=db,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        action="PERMISSION_REVOKED",
        document_id=doc.id,
        target_user_id=target_user_id,
        outcome=AuditOutcome.SUCCESS,
        reason_code="IMMEDIATE_REVOCATION_EXECUTED",
        request_id=str(uuid.uuid4()),
    )

    return {"status": "success", "message": "Permission revoked immediately."}

# ==========================================
# AUDIT & INTEGRITY ENDPOINTS
# ==========================================

@app.get("/api/audit/verify", response_model=AuditVerificationResponse, tags=["Audit"])
def verify_audit_trail(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    result = AuditService.verify_chain(db)
    AuditService.record_event(
        db=db,
        actor_user_id=current_user.id,
        actor_email=current_user.email,
        action="AUDIT_INTEGRITY_CHECK",
        document_id=None,
        target_user_id=None,
        outcome=AuditOutcome.SUCCESS if result["is_valid"] else AuditOutcome.DENIED,
        reason_code="CHAIN_VERIFICATION_ROUTINE",
        request_id=str(uuid.uuid4()),
        metadata={"is_valid": result["is_valid"], "total": result["total_events"]},
    )
    return AuditVerificationResponse(**result)
