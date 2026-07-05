from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # App
    APP_ENV: str = "development"
    SECRET_KEY: str = "change-me-in-production"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://phishguard:phishguard@localhost:5432/phishguard"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL_SECONDS: int = 3600       # 1 hour per scanned domain

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",         # React dev server
        "http://localhost:5173",         # Vite dev server
        "http://127.0.0.1:3000",
    ]

    # ML model paths
    MODEL_PATH: str = "models/xgb_model.pkl"
    ENSEMBLE_MODEL_PATH: str = "models/ensemble_model.pkl"

    # Feature extraction timeouts (seconds)
    DNS_TIMEOUT: int = 5
    WHOIS_TIMEOUT: int = 8
    SSL_TIMEOUT: int = 5
    SCREENSHOT_TIMEOUT: int = 10

    # Scan thresholds
    HIGH_RISK_THRESHOLD: int = 70        # score >= 70 → PHISHING
    MEDIUM_RISK_THRESHOLD: int = 40      # score 40–69 → SUSPICIOUS

    # Rate limiting
    RATE_LIMIT: str = "30/minute"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
