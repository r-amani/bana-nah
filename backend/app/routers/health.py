"""
PHANTOM Health Check Router
"""
from datetime import datetime
from fastapi import APIRouter
from app.database import get_db
from app.scanner.orchestrator import orchestrator

router = APIRouter()


@router.get("/health", summary="Health check")
async def health_check():
    """Check service health and connectivity."""
    health = {
        "status": "healthy",
        "service": "PHANTOM Backend",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {},
    }

    # Check MongoDB
    try:
        db = get_db()
        await db.command("ping")
        health["components"]["mongodb"] = {"status": "connected"}
    except Exception as e:
        health["components"]["mongodb"] = {"status": "disconnected", "error": str(e)}
        health["status"] = "degraded"

    # Check registered modules
    modules = orchestrator.list_modules()
    health["components"]["scanner"] = {
        "registered_modules": len(modules),
        "modules": modules,
    }

    return health
