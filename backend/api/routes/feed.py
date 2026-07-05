from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from db.session import get_db
from db.models import ScanResult, ThreatFeed

router = APIRouter()


@router.get("/feed", summary="Live threat detection feed")
async def get_feed(
    limit: int = Query(default=50, le=200),
    page: int = Query(default=1, ge=1),
    category: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * limit
    query = select(ThreatFeed).order_by(desc(ThreatFeed.flagged_at)).offset(offset).limit(limit)
    if category:
        query = query.where(ThreatFeed.category == category)
    result = await db.execute(query)
    items = result.scalars().all()
    return {
        "items": [
            {
                "id": i.id,
                "domain": i.domain,
                "score": i.score,
                "verdict": i.verdict,
                "category": i.category,
                "flagged_at": i.flagged_at,
                "scan_id": i.scan_id,
            }
            for i in items
        ],
        "page": page,
        "limit": limit,
    }


@router.get("/stats", summary="Dashboard metrics")
async def get_stats(db: AsyncSession = Depends(get_db)):
    from datetime import datetime, timedelta
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Threats today
    threats_today = await db.execute(
        select(func.count(ThreatFeed.id)).where(ThreatFeed.flagged_at >= today_start)
    )
    # Average confidence
    avg_conf = await db.execute(
        select(func.avg(ScanResult.confidence)).where(ScanResult.created_at >= today_start)
    )
    # Zero-day count
    zero_day = await db.execute(
        select(func.count(ScanResult.id)).where(
            ScanResult.is_zero_day == True,
            ScanResult.created_at >= today_start,
        )
    )
    return {
        "threats_today": threats_today.scalar() or 0,
        "avg_confidence": round((avg_conf.scalar() or 0) * 100, 1),
        "zero_day_count": zero_day.scalar() or 0,
        "cert_alerts_count": 0,  # updated in Phase 5
    }


@router.get("/scan/{scan_id}", summary="Get a scan result by ID")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanResult).where(ScanResult.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
