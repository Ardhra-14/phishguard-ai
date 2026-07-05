from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.session import get_db
from db.models import ScanResult

router = APIRouter()


@router.get("/report/{scan_id}", summary="Generate CERT-In incident report")
async def generate_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """
    Generates a structured CERT-In incident report for a scan result.
    Full PDF generation wired in Phase 5.
    """
    result = await db.execute(select(ScanResult).where(ScanResult.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Stub — Phase 5 replaces this with WeasyPrint PDF generation
    return JSONResponse({
        "incident_id": f"IR-2024-PH-{scan_id[:4].upper()}",
        "domain": scan.domain,
        "score": scan.score,
        "verdict": scan.verdict,
        "status": "report_generation_available_in_phase5",
    })
