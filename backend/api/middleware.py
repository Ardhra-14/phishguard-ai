import time
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from core.config import settings

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT])


def register_middlewares(app: FastAPI):
    # Rate limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Add X-Scan-Duration header and catch unhandled exceptions
    @app.middleware("http")
    async def timing_and_error_middleware(request: Request, call_next):
        start = time.time()
        try:
            response = await call_next(request)
            duration_ms = int((time.time() - start) * 1000)
            response.headers["X-Scan-Duration"] = str(duration_ms)
            return response
        except Exception as exc:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_server_error",
                    "message": "An unexpected error occurred. Please try again.",
                    "detail": str(exc) if settings.APP_ENV == "development" else None,
                },
            )
