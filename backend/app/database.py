"""
PHANTOM MongoDB Connection Manager
Provides async MongoDB connectivity via Motor.
"""
import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config import get_settings

logger = logging.getLogger("phantom.database")

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def connect_db() -> None:
    """Establish MongoDB connection and create indexes."""
    global _client, _db
    settings = get_settings()
    logger.info("Connecting to MongoDB....")
    _client = AsyncIOMotorClient(
        settings.mongodb_uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
    )
    _db = _client[settings.mongodb_db_name]

    # Verify connection
    try:
        await _client.admin.command("ping")
        logger.info("MongoDB connection established — database: %s", settings.mongodb_db_name)
    except Exception as e:
        logger.error("MongoDB connection failed: %s", e)
        raise

    # Create indexes
    await _create_indexes()


async def _create_indexes() -> None:
    """Create database indexes for performance."""
    db = get_db()

    # Scans collection
    await db.scans.create_index("scan_id", unique=True)
    await db.scans.create_index("target_url")
    await db.scans.create_index("status")
    await db.scans.create_index("created_at")

    # Findings collection
    await db.findings.create_index("scan_id")
    await db.findings.create_index("module")
    await db.findings.create_index([("scan_id", 1), ("module", 1)])

    # Reports collection
    await db.reports.create_index("report_id", unique=True)
    await db.reports.create_index("reporter_ip")
    await db.reports.create_index("hostname")
    await db.reports.create_index("created_at")

    # Entities collection
    await db.entities.create_index("entity_id", unique=True)
    await db.entities.create_index("type")
    await db.entities.create_index("value")
    await db.entities.create_index([("type", 1), ("value", 1)], unique=True)

    # Relationships collection
    await db.relationships.create_index("source_entity_id")
    await db.relationships.create_index("target_entity_id")
    await db.relationships.create_index("scan_id")

    logger.info("Database indexes created")


async def close_db() -> None:
    """Close MongoDB connection."""
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
        logger.info("MongoDB connection closed")


def get_db() -> AsyncIOMotorDatabase:
    """Return the database instance. Raises if not connected."""
    if _db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _db
