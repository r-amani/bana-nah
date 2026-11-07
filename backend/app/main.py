"""
PHANTOM — Phishing Detection & Digital Threat Investigation Platform
Main FastAPI Application Entry Point
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.database import connect_db, close_db
from app.routers import scans, domains, reports, entities, graph, health
from app.scanner.orchestrator import orchestrator
from app.scanner.modules.placeholder import PlaceholderModule
from app.scanner.modules.url_detection import UrlDetectionModule
from app.scanner.modules.tls_validation import TlsValidationModule
from app.scanner.modules.security_assessment import SecurityAssessmentModule
from app.scanner.modules.risk_scoring import RiskScoringModule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-25s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("phantom")

settings = get_settings()

# Rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.rate_limit_requests}/{settings.rate_limit_window_seconds}seconds"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info("=" * 60)
    logger.info("  PHANTOM Backend Starting")
    logger.info("=" * 60)

    # Connect to MongoDB
    try:
        await connect_db()
    except Exception as e:
        logger.warning("MongoDB not available at startup: %s. Some features will be degraded.", e)

    yield

    # Shutdown
    logger.info("PHANTOM Backend shutting down...")
    await close_db()


app = FastAPI(
    title="PHANTOM",
    description="Phishing Detection & Digital Threat Investigation Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Rate limiter state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware — allow frontend dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__},
    )


# Register scan modules
orchestrator.register_module(PlaceholderModule())
orchestrator.register_module(UrlDetectionModule())
orchestrator.register_module(TlsValidationModule())
orchestrator.register_module(SecurityAssessmentModule())
orchestrator.register_module(RiskScoringModule())

# Register routers
app.include_router(health.router, tags=["Health"])
app.include_router(scans.router, prefix="/api", tags=["Scans"])
app.include_router(domains.router, prefix="/api", tags=["Domains"])
app.include_router(reports.router, prefix="/api", tags=["Reports"])
app.include_router(entities.router, prefix="/api", tags=["Entities"])
app.include_router(graph.router, prefix="/api", tags=["Graph"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=settings.debug)
