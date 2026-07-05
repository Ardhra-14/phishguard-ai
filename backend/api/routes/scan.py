import time
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import get_db
from db.models import ScanResult, ThreatFeed
from core.config import settings

router = APIRouter()


# ── Request / Response schemas ────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > 500:
            raise ValueError("URL too long (max 500 chars)")
        # Add scheme if missing so downstream parsers work
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v


class ShapFeature(BaseModel):
    feature: str
    label: str
    value: float
    shap_value: float
    direction: str          # "phishing" | "safe"


class ScanResponse(BaseModel):
    scan_id: str
    domain: str
    url: str
    score: int              # 0–100
    verdict: str            # PHISHING | SUSPICIOUS | SAFE
    confidence: float
    category: str | None
    is_zero_day: bool
    domain_age_days: int | None
    registrar: str | None
    ssl_issuer: str | None
    visual_similarity: float | None
    closest_brand: str | None
    features: dict
    shap: list[ShapFeature]
    scan_duration_ms: int


# ── Background task: persist result ──────────────────────────────────────────

async def _persist_scan(result_data: dict, db: AsyncSession):
    """Save scan result to PostgreSQL and update threat feed."""
    try:
        scan = ScanResult(id=result_data["scan_id"], **{k: v for k, v in result_data.items() if k != "scan_id"})
        db.add(scan)

        if result_data["score"] >= settings.MEDIUM_RISK_THRESHOLD:
            feed_entry = ThreatFeed(
                domain=result_data["domain"],
                score=result_data["score"],
                verdict=result_data["verdict"],
                category=result_data.get("category"),
                scan_id=result_data["id"],
            )
            db.add(feed_entry)

        await db.commit()
    except Exception as e:
        print(f"[persist_scan] error: {e}")
        await db.rollback()


# ── Scan endpoint ─────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResponse, summary="Analyse a domain for phishing signals")
async def scan_domain(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),  # type: ignore[assignment]
):
    """
    Full multi-signal phishing analysis:
    - URL lexical features
    - DNS / WHOIS inspection
    - SSL/TLS certificate audit
    - Visual clone detection
    - IDN homograph check
    - XGBoost + RF ensemble scoring
    - SHAP explainability
    """
    start_ms = int(time.time() * 1000)

    # ── Phase 0 stub — real feature pipeline wired in Phase 2–4 ──────────────
    # Import here so app starts even before ML deps are installed
    try:
        from features.pipeline import FeaturePipeline
        from ml.predictor import Predictor

        pipeline = FeaturePipeline()
        features = await pipeline.extract(req.url)
        predictor = Predictor()
        result = predictor.predict(features)
    except ImportError:
        # Stub response while ML modules are being built
        result = _stub_result(req.url)

    duration_ms = int(time.time() * 1000) - start_ms

    # Build response dict
    import uuid
    from urllib.parse import urlparse
    domain = urlparse(req.url).netloc or req.url

    response_data = {
        "scan_id": str(uuid.uuid4()),
        "domain": domain,
        "url": req.url,
        "score": result["score"],
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "category": result.get("category"),
        "is_zero_day": result.get("is_zero_day", False),
        "domain_age_days": result.get("domain_age_days"),
        "registrar": result.get("registrar"),
        "ssl_issuer": result.get("ssl_issuer"),
        "visual_similarity": result.get("visual_similarity"),
        "closest_brand": result.get("closest_brand"),
        "features": result.get("features", {}),
        "shap": result.get("shap", []),
        "scan_duration_ms": duration_ms,
    }

    # Persist to DB in background — skip gracefully if DB unavailable
    if db is not None:
        background_tasks.add_task(_persist_scan, response_data.copy(), db)

    return ScanResponse(**response_data)


def _stub_result(url: str) -> dict:
    """
    Stub result used in Phase 0 before ML pipeline is ready.
    Removed once FeaturePipeline and Predictor are implemented.
    """
    from urllib.parse import urlparse
    domain = urlparse(url).netloc or url
    score = 85 if any(k in domain for k in ["sbi","hdfc","upi","verify","secure","login","bank"]) else 12
    verdict = "PHISHING" if score >= 70 else ("SUSPICIOUS" if score >= 40 else "SAFE")
    return {
        "score": score,
        "verdict": verdict,
        "confidence": score / 100,
        "category": "banking",
        "is_zero_day": True,
        "domain_age_days": 3,
        "registrar": "Namecheap Inc.",
        "ssl_issuer": "Let's Encrypt",
        "visual_similarity": 0.89,
        "closest_brand": "SBI",
        "features": {"stub": True},
        "shap": [],
    }
