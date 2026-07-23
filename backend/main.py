from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import scan, feed, report
from api.middleware import register_middlewares
from db.session import init_db
from core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    print("🚀 PhishGuard AI starting up...")
    await init_db()
    print("✅ Database initialized")
    # ML model is loaded lazily on first scan request
    yield
    # Shutdown
    print("🛑 PhishGuard AI shutting down...")


app = FastAPI(
    title="PhishGuard AI",
    description="Real-time phishing domain detection — NTRO / CERT-In",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow the React frontend origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_middlewares(app)

# Routers
app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
app.include_router(feed.router, prefix="/api/v1", tags=["feed"])
app.include_router(report.router, prefix="/api/v1", tags=["report"])


# Root endpoint
@app.get("/", tags=["home"])
async def root():
    return {
        "service": "PhishGuard AI",
        "status": "Running",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


# Health endpoint
@app.get("/health", tags=["health"])
async def health_check():
    return {
        "status": "ok",
        "version": "1.0.0",
        "service": "PhishGuard AI"
    }