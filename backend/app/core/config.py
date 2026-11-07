import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "TrustVault Secure Document Management"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "trustvault-production-secret-key-replace-in-env-9281")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120  # 2 hours short-lived token
    ALGORITHM: str = "HS256"

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./storage/trustvault.db"
    )

    # Storage
    STORAGE_DIR: str = os.getenv("STORAGE_DIR", "./storage/documents")
    MAX_FILE_SIZE_MB: int = 50

    # Rate limiting
    LOGIN_RATE_LIMIT_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_SECONDS: int = 300

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
