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
    ai_verified: bool = False
    ai_verdict: str | None = None
    ai_reason: str | None = None
    scan_duration_ms: int


# ── Background task: persist result ──────────────────────────────────────────

async def _persist_scan(result_data: dict, db: AsyncSession):
    """Save scan result to PostgreSQL and update threat feed.

    Phase 3.7 fix (open issue #1 from the Phase 3.6 summary): ScanResult's
    columns are named `features_json` / `shap_json`, not `features` / `shap`
    (see db/models.py). Blindly spreading result_data's keys into
    ScanResult(**...) raised "'features' is an invalid keyword argument for
    ScanResult" on every successful scan, silently caught below - so nothing
    was ever actually persisted with its feature/SHAP breakdown. Remapped
    explicitly instead of spreading the dict.

    Also fixes a second latent bug: the ThreatFeed insert below referenced
    result_data["id"], but result_data only has a "scan_id" key - this
    keyword also raised (also silently swallowed) any time score crossed
    settings.MEDIUM_RISK_THRESHOLD.
    """
    try:
        scan = ScanResult(
            id=result_data["scan_id"],
            domain=result_data["domain"],
            url=result_data["url"],
            score=result_data["score"],
            verdict=result_data["verdict"],
            confidence=result_data["confidence"],
            category=result_data.get("category"),
            is_zero_day=result_data.get("is_zero_day", False),
            features_json=result_data.get("features", {}),
            shap_json=result_data.get("shap", []),
            domain_age_days=result_data.get("domain_age_days"),
            registrar=result_data.get("registrar"),
            ssl_issuer=result_data.get("ssl_issuer"),
            visual_similarity=result_data.get("visual_similarity"),
            closest_brand=result_data.get("closest_brand"),
            scan_duration_ms=result_data.get("scan_duration_ms"),
        )
        db.add(scan)

        if result_data["score"] >= settings.MEDIUM_RISK_THRESHOLD:
            feed_entry = ThreatFeed(
                domain=result_data["domain"],
                score=result_data["score"],
                verdict=result_data["verdict"],
                category=result_data.get("category"),
                scan_id=result_data["scan_id"],
            )
            db.add(feed_entry)

        await db.commit()
    except Exception as e:
        print(f"[persist_scan] error: {e}")
        await db.rollback()


# ── Scan endpoint ─────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResponse, summary="Analyse a domain for phishing signals")
@router.post("/check-url", response_model=ScanResponse, summary="Analyse a domain for phishing signals (alias)")
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

    # ── Real feature pipeline + ML ensemble (Phase 2-3.6) ────────────────────
    # Import here so app still starts even before ML deps are installed.
    #
    # Phase 3.6 fix: import the module-level `predictor` singleton, NOT the
    # `Predictor` class. Instantiating Predictor() per-request reloaded the
    # joblib model, meta.json, preprocessing artifacts, and rebuilt both SHAP
    # TreeExplainers from scratch on every single scan - defeating the whole
    # point of loading them once at import time.
    try:
        from features.pipeline import FeaturePipeline
        from ml.predictor import predictor

        pipeline = FeaturePipeline()
        features = await pipeline.extract(req.url)
        result = predictor.predict(features)
    except ImportError:
        # Stub response while ML modules are being built
        result = _stub_result(req.url)

    from urllib.parse import urlparse
    domain = urlparse(req.url).netloc or req.url

    # ── High-Speed AI Confirmation Filter ────────────────────────────────────
    # Triggered ONLY if the initial classifier flags PHISHING or SUSPICIOUS.
    # If SAFE, AI is NOT invoked (0ms overhead).
    ai_verified = False
    ai_verdict = None
    ai_reason = None

    try:
        from ml.ai_filter import ai_filter

        if ai_filter.should_evaluate(result["verdict"], result["score"]):
            ai_res = await ai_filter.verify_threat(
                url=req.url,
                domain=domain,
                initial_score=result["score"],
                initial_verdict=result["verdict"],
                closest_brand=result.get("closest_brand"),
                category=result.get("category"),
            )
            ai_verified = ai_res.get("ai_verified", True)
            ai_verdict = ai_res.get("ai_verdict")
            ai_reason = ai_res.get("ai_reason")
            result["verdict"] = ai_res.get("verdict", result["verdict"])
            result["score"] = ai_res.get("score", result["score"])
    except Exception as e:
        print(f"[AIFilter] Error: {e}")

    duration_ms = int(time.time() * 1000) - start_ms

    # Build response dict
    import uuid

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
        "ai_verified": ai_verified,
        "ai_verdict": ai_verdict,
        "ai_reason": ai_reason,
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


# ── Manual screenshot upload endpoint (Phase 4 - Visual Detection) ──────────
# Accepts a directly uploaded screenshot, for cases with no live URL to visit
# (e.g. a screenshot forwarded from a phishing email or SMS).

from fastapi import UploadFile, File
from features.visual.visual_scoring import analyze_screenshot


class ImageScanResponse(BaseModel):
    verdict: str
    confidence: float
    score: int
    reasons: list[str]
    visual_similarity_score: float | None
    dom_credential_form_detected: bool
    closest_brand: str | None


@router.post("/scan/image", response_model=ImageScanResponse, summary="Analyse an uploaded screenshot for phishing signals")
async def scan_image(file: UploadFile = File(...)):
    """
    Standalone visual analysis of an uploaded screenshot - independent of
    the URL-based /scan pipeline. No claimed_domain is available here, so
    brand-similarity matches are conservatively flagged (see
    visual_scoring.py docstring for that trade-off).
    """
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Uploaded file must be an image")

    screenshot_bytes = await file.read()

    try:
        analysis = analyze_screenshot(screenshot_bytes, claimed_domain=None)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Could not process image: {e}")

    return ImageScanResponse(
        verdict=analysis["verdict"],
        confidence=analysis["confidence"],
        score=analysis["score"],
        reasons=analysis["reasons"],
        visual_similarity_score=analysis["visual_similarity_score"],
        dom_credential_form_detected=analysis["dom_credential_form_detected"],
        closest_brand=analysis["details"]["brand_similarity"]["closest_brand"],
    )