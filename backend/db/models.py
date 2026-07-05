import uuid
from datetime import datetime
from sqlalchemy import String, Integer, Float, DateTime, JSON, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column
from db.session import Base


class ScanResult(Base):
    """Stores every domain scan result with full feature + SHAP data."""
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    domain: Mapped[str]         = mapped_column(String(500), index=True, nullable=False)
    url: Mapped[str]            = mapped_column(Text, nullable=False)
    score: Mapped[int]          = mapped_column(Integer, nullable=False)      # 0–100
    verdict: Mapped[str]        = mapped_column(String(20), nullable=False)   # PHISHING / SUSPICIOUS / SAFE
    confidence: Mapped[float]   = mapped_column(Float, nullable=False)
    category: Mapped[str]       = mapped_column(String(20), nullable=True)    # upi / banking / gov / generic
    is_zero_day: Mapped[bool]   = mapped_column(Boolean, default=False)       # not in any known blacklist

    # Full feature vector and SHAP values stored as JSON
    features_json: Mapped[dict] = mapped_column(JSON, nullable=True)
    shap_json: Mapped[list]     = mapped_column(JSON, nullable=True)

    # Domain metadata
    domain_age_days: Mapped[int]   = mapped_column(Integer, nullable=True)
    registrar: Mapped[str]         = mapped_column(String(200), nullable=True)
    ssl_issuer: Mapped[str]        = mapped_column(String(200), nullable=True)
    visual_similarity: Mapped[float] = mapped_column(Float, nullable=True)
    closest_brand: Mapped[str]     = mapped_column(String(100), nullable=True)

    # CERT-In report
    incident_id: Mapped[str]    = mapped_column(String(50), nullable=True)
    report_generated: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    scan_duration_ms: Mapped[int] = mapped_column(Integer, nullable=True)


class ThreatFeed(Base):
    """Aggregated live threat intelligence feed."""
    __tablename__ = "threat_feed"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    domain: Mapped[str]     = mapped_column(String(500), nullable=False, index=True)
    score: Mapped[int]      = mapped_column(Integer, nullable=False)
    verdict: Mapped[str]    = mapped_column(String(20), nullable=False)
    category: Mapped[str]   = mapped_column(String(20), nullable=True)
    flagged_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    scan_id: Mapped[str]    = mapped_column(String(36), nullable=True)        # FK to scan_results.id
