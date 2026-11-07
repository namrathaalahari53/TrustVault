from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    department: Optional[str] = "General"
    role: str = "VIEWER"

class UserCreate(UserBase):
    password: Optional[str] = None

class UserResponse(UserBase):
    id: str
    is_active: bool
    must_change_password: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10)
    full_name: str
    department: Optional[str] = "General"
    role: Optional[str] = "OWNER"

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10)

class DocumentBase(BaseModel):
    title: str
    description: Optional[str] = ""
    category: Optional[str] = "General"

class DocumentCreate(DocumentBase):
    pass

class DocumentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    content: Optional[str] = None

class DocumentResponse(DocumentBase):
    id: str
    owner_id: str
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    original_filename: str
    mime_type: str
    file_size: int
    sha256_checksum: str
    document_status: str
    created_at: datetime
    updated_at: datetime
    user_permission: Optional[str] = "NONE"
    is_owner: bool = False

    class Config:
        from_attributes = True

class PermissionGrantRequest(BaseModel):
    target_email: EmailStr
    permission_level: str = Field(pattern="^(READ|EDIT)$")

class PermissionResponse(BaseModel):
    id: str
    document_id: str
    user_id: str
    user_email: str
    user_name: str
    permission_level: str
    granted_at: datetime

    class Config:
        from_attributes = True

class AuditEventResponse(BaseModel):
    id: str
    event_id: str
    sequence_number: int
    actor_user_id: Optional[str]
    actor_email: str
    action: str
    document_id: Optional[str]
    target_user_id: Optional[str]
    timestamp: datetime
    outcome: str
    reason_code: str
    request_id: str
    metadata_json: str
    previous_hash: str
    canonical_hash: str
    event_hash: str

    class Config:
        from_attributes = True

class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_events: int
    verified_events: int
    tampered_event_id: Optional[str]
    tampered_sequence: Optional[int]
    error_message: Optional[str]
    genesis_hash: str
    latest_event_hash: str
    chain_head_timestamp: Optional[datetime]
