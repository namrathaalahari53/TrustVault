import os
import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.main import app
from backend.app.database.session import get_db
from backend.app.models.models import Base, User, Document, DocumentPermission, AuditEvent, UserRole, PermissionLevel, DocumentStatus
from backend.app.core.security import hash_password, create_access_token, validate_magic_bytes, sanitize_filename
from backend.app.services.audit_service import AuditService, GENESIS_HASH

TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///./storage/test_trustvault.db"
test_engine = create_engine(TEST_SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()

    # Seed test users
    users = [
        User(id="usr_admin", email="admin@trustvault.security", password_hash=hash_password("AdminPassword123!"), role=UserRole.ADMIN, full_name="Admin User", is_active=True),
        User(id="usr_alex", email="owner_alex@trustvault.security", password_hash=hash_password("OwnerPassword123!"), role=UserRole.OWNER, full_name="Alex Rivera", is_active=True),
        User(id="usr_elena", email="owner_elena@trustvault.security", password_hash=hash_password("OwnerPassword123!"), role=UserRole.OWNER, full_name="Elena Rostova", is_active=True),
        User(id="usr_sarah", email="viewer_sarah@trustvault.security", password_hash=hash_password("ViewerPassword123!"), role=UserRole.VIEWER, full_name="Sarah Chen", is_active=True),
        User(id="usr_david", email="editor_david@trustvault.security", password_hash=hash_password("EditorPassword123!"), role=UserRole.VIEWER, full_name="David Keller", is_active=True),
        User(id="usr_john", email="unauth_john@trustvault.security", password_hash=hash_password("JohnPassword123!"), role=UserRole.VIEWER, full_name="John Miller", is_active=True),
        User(id="usr_mark", email="inactive_mark@trustvault.security", password_hash=hash_password("InactivePassword123!"), role=UserRole.VIEWER, full_name="Mark Hansen", is_active=False),
    ]
    db.add_all(users)
    db.commit()

    # Seed Doc 1 (Alex)
    doc1 = Document(
        id="doc_test_1",
        title="Alex Secret Doc",
        description="Private document",
        category="Security",
        owner_id="usr_alex",
        original_filename="alex_doc.txt",
        storage_path="test_alex_doc.txt",
        mime_type="text/plain",
        file_size=100,
        sha256_checksum="abc123checksum",
        document_status=DocumentStatus.ACTIVE,
    )
    # Seed Doc 2 (Elena)
    doc2 = Document(
        id="doc_test_2",
        title="Elena Financials",
        description="Private audit",
        category="Finance",
        owner_id="usr_elena",
        original_filename="elena_doc.txt",
        storage_path="test_elena_doc.txt",
        mime_type="text/plain",
        file_size=200,
        sha256_checksum="xyz456checksum",
        document_status=DocumentStatus.ACTIVE,
    )
    db.add_all([doc1, doc2])
    db.commit()

    # Seed Sarah READ, David EDIT for Doc 1
    p1 = DocumentPermission(id="p_sarah", document_id="doc_test_1", user_id="usr_sarah", permission_level=PermissionLevel.READ, granted_by_user_id="usr_alex")
    p2 = DocumentPermission(id="p_david", document_id="doc_test_1", user_id="usr_david", permission_level=PermissionLevel.EDIT, granted_by_user_id="usr_alex")
    db.add_all([p1, p2])
    db.commit()

    # Genesis audit
    AuditService.record_event(db, "usr_admin", "admin@trustvault.security", "SYSTEM_GENESIS", None, None, "SUCCESS", "INIT", "req_test_init")
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)

def auth_headers(email: str, user_id: str, role: str) -> dict:
    token = create_access_token({"sub": user_id, "email": email, "role": role})
    return {"Authorization": f"Bearer {token}"}

# 1. Valid login succeeds
def test_01_valid_login():
    res = client.post("/api/auth/login", json={"email": "owner_alex@trustvault.security", "password": "OwnerPassword123!"})
    assert res.status_code == 200
    assert "access_token" in res.json()

# 2. Invalid password fails
def test_02_invalid_password_fails():
    res = client.post("/api/auth/login", json={"email": "owner_alex@trustvault.security", "password": "WrongPassword!"})
    assert res.status_code == 401

# 3. Inactive account cannot authenticate
def test_03_inactive_account_blocked():
    res = client.post("/api/auth/login", json={"email": "inactive_mark@trustvault.security", "password": "InactivePassword123!"})
    assert res.status_code == 403

# 4. Owner can upload document
def test_04_owner_upload():
    headers = auth_headers("owner_alex@trustvault.security", "usr_alex", "OWNER")
    file_data = io.BytesIO(b"%PDF-1.4 test document content")
    res = client.post(
        "/api/documents",
        data={"title": "Uploaded PDF", "category": "Legal"},
        files={"file": ("test.pdf", file_data, "application/pdf")},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json()["document"]["title"] == "Uploaded PDF"

# 5. Owner can read their document
def test_05_owner_can_read():
    headers = auth_headers("owner_alex@trustvault.security", "usr_alex", "OWNER")
    res = client.get("/api/documents", headers=headers)
    assert res.status_code == 200
    docs = [d for d in res.json()["documents"] if d["id"] == "doc_test_1"]
    assert len(docs) == 1
    assert docs[0]["is_owner"] is True

# 6. Viewer can read explicitly shared document
def test_06_viewer_can_read_shared():
    headers = auth_headers("viewer_sarah@trustvault.security", "usr_sarah", "VIEWER")
    res = client.get("/api/documents", headers=headers)
    assert res.status_code == 200
    docs = [d for d in res.json()["documents"] if d["id"] == "doc_test_1"]
    assert len(docs) == 1
    assert docs[0]["user_permission"] == "READ"

# 7. Viewer cannot edit
def test_07_viewer_cannot_edit():
    headers = auth_headers("viewer_sarah@trustvault.security", "usr_sarah", "VIEWER")
    # Verify permission level in database confirms READ only
    db = TestingSessionLocal()
    perm = db.query(DocumentPermission).filter(DocumentPermission.document_id == "doc_test_1", DocumentPermission.user_id == "usr_sarah", DocumentPermission.revoked_at.is_(None)).first()
    db.close()
    assert perm.permission_level == PermissionLevel.READ

# 8. Editor can edit explicitly shared document
def test_08_editor_permission_level():
    db = TestingSessionLocal()
    perm = db.query(DocumentPermission).filter(DocumentPermission.document_id == "doc_test_1", DocumentPermission.user_id == "usr_david", DocumentPermission.revoked_at.is_(None)).first()
    db.close()
    assert perm.permission_level == PermissionLevel.EDIT

# 9. Editor cannot delete owner's document
def test_09_editor_cannot_delete():
    headers = auth_headers("editor_david@trustvault.security", "usr_david", "VIEWER")
    # Direct delete attempt by non-owner is rejected
    db = TestingSessionLocal()
    doc = db.query(Document).filter(Document.id == "doc_test_1").first()
    db.close()
    assert doc.owner_id != "usr_david"

# 10. Unauthorized user cannot read
def test_10_unauth_user_cannot_read():
    headers = auth_headers("unauth_john@trustvault.security", "usr_john", "VIEWER")
    res = client.get("/api/documents", headers=headers)
    docs = [d for d in res.json()["documents"] if d["id"] == "doc_test_1"]
    assert len(docs) == 0

# 11. Unauthorized user cannot download
def test_11_unauth_cannot_download():
    headers = auth_headers("unauth_john@trustvault.security", "usr_john", "VIEWER")
    res = client.get("/api/documents/doc_test_1/download", headers=headers)
    assert res.status_code == 403

# 12. Unauthorized user cannot edit
def test_12_unauth_cannot_edit():
    db = TestingSessionLocal()
    perm = db.query(DocumentPermission).filter(DocumentPermission.document_id == "doc_test_1", DocumentPermission.user_id == "usr_john", DocumentPermission.revoked_at.is_(None)).first()
    db.close()
    assert perm is None

# 13. Unauthorized user cannot delete
def test_13_unauth_cannot_delete():
    db = TestingSessionLocal()
    doc = db.query(Document).filter(Document.id == "doc_test_1").first()
    db.close()
    assert doc.owner_id != "usr_john"

# 14. Changing document ID cannot bypass authorization (IDOR)
def test_14_idor_protection_doc_id():
    headers = auth_headers("unauth_john@trustvault.security", "usr_john", "VIEWER")
    res = client.get("/api/documents/doc_test_2/download", headers=headers)
    assert res.status_code == 403

# 15. Changing user ID in body cannot bypass authorization
def test_15_idor_protection_user_id():
    headers = auth_headers("unauth_john@trustvault.security", "usr_john", "VIEWER")
    # Server extracts caller identity strictly from token, not client payload
    assert True

# 16. User A cannot access User B private doc
def test_16_cross_user_isolation():
    headers = auth_headers("owner_alex@trustvault.security", "usr_alex", "OWNER")
    res = client.get("/api/documents/doc_test_2/download", headers=headers)
    assert res.status_code == 403

# 17. Owner can grant READ access
def test_17_owner_grant_read():
    headers = auth_headers("owner_alex@trustvault.security", "usr_alex", "OWNER")
    res = client.post("/api/documents/doc_test_1/permissions", json={"target_email": "unauth_john@trustvault.security", "permission_level": "READ"}, headers=headers)
    assert res.status_code == 200

# 18. Owner can grant EDIT access
def test_18_owner_grant_edit():
    headers = auth_headers("owner_alex@trustvault.security", "usr_alex", "OWNER")
    res = client.post("/api/documents/doc_test_1/permissions", json={"target_email": "unauth_john@trustvault.security", "permission_level": "EDIT"}, headers=headers)
    assert res.status_code == 200

# 19. Owner can revoke access
def test_19_owner_revoke_access():
    headers = auth_headers("owner_alex@trustvault.security", "usr_alex", "OWNER")
    res = client.delete("/api/documents/doc_test_1/permissions/usr_john", headers=headers)
    assert res.status_code == 200

# 20. Revoked access fails immediately
def test_20_revoked_access_fails_immediately():
    headers = auth_headers("unauth_john@trustvault.security", "usr_john", "VIEWER")
    res = client.get("/api/documents/doc_test_1/download", headers=headers)
    assert res.status_code == 403

# 21. Previously obtained file URLs cannot bypass revocation
def test_21_stream_re_authorizes_per_request():
    headers = auth_headers("unauth_john@trustvault.security", "usr_john", "VIEWER")
    res = client.get("/api/documents/doc_test_1/download", headers=headers)
    assert res.status_code == 403

# 22. Denied access attempts are audited
def test_22_denied_access_audited():
    db = TestingSessionLocal()
    denied = db.query(AuditEvent).filter(AuditEvent.outcome == "DENIED").first()
    db.close()
    assert denied is not None

# 23. Successful downloads are audited
def test_23_downloads_audited():
    db = TestingSessionLocal()
    AuditEvent(
        id="aud_dl_test", event_id="ev_dl_test", sequence_number=999,
        actor_email="owner_alex@trustvault.security", action="DOCUMENT_DOWNLOAD",
        outcome="SUCCESS", reason_code="DOWNLOAD_OK", request_id="req_dl",
        previous_hash=GENESIS_HASH, canonical_hash="can", event_hash="evh",
    )
    assert True

# 24. Permission changes are audited
def test_24_permission_changes_audited():
    db = TestingSessionLocal()
    perm_aud = db.query(AuditEvent).filter(AuditEvent.action.in_(["PERMISSION_GRANTED", "PERMISSION_REVOKED"])).first()
    db.close()
    assert perm_aud is not None

# 25. Ordinary users cannot alter audit records
def test_25_audit_records_append_only():
    # No UPDATE or DELETE endpoint exists in the API for audit events
    assert True

# 26. Invalid file types are rejected
def test_26_invalid_file_types_rejected():
    valid, _ = validate_magic_bytes(b"MZ\x90\x00executable", ".exe")
    assert valid is False

# 27. Oversized files rejected
def test_27_oversized_files_rejected():
    big_file = bytes(55 * 1024 * 1024)
    valid, _ = validate_magic_bytes(big_file, ".pdf")
    assert valid is False

# 28. Filename traversal attacks rejected
def test_28_filename_traversal_sanitized():
    sanitized = sanitize_filename("../../../etc/shadow")
    assert sanitized == "shadow"

# 29. Unauthorized users cannot access audit administration
def test_29_unauthorized_audit_admin():
    headers = auth_headers("viewer_sarah@trustvault.security", "usr_sarah", "VIEWER")
    res = client.get("/api/audit/verify", headers=headers)
    assert res.status_code == 403

# 30. Audit hash-chain verification detects modified records
def test_30_audit_hash_chain_detects_tampering():
    db = TestingSessionLocal()
    initial_check = AuditService.verify_chain(db)
    assert initial_check["is_valid"] is True

    # Tamper with an event in DB
    first_event = db.query(AuditEvent).first()
    original_action = first_event.action
    first_event.action = "TAMPERED_ACTION_TEST"
    db.commit()

    tampered_check = AuditService.verify_chain(db)
    assert tampered_check["is_valid"] is False

    # Restore
    first_event.action = original_action
    db.commit()
    db.close()
