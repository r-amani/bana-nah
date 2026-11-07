"""
PHANTOM Placeholder Module
Demonstrates the module interface for other computers to implement.

This module does NOT perform real detection — it only validates that
the module registration and orchestration pipeline is functional.
"""
import logging
from datetime import datetime

from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.placeholder")


class PlaceholderModule(ModuleInterface):
    """
    Placeholder module that validates pipeline connectivity.
    Replace this with real detection modules.
    """

    name = "placeholder"
    description = "Pipeline validation placeholder (no real detection)"
    version = "0.1.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Placeholder module executing for %s (scan %s)", hostname, scan_id)

        return {
            "data": {
                "message": "Placeholder module executed successfully",
                "target_url": target_url,
                "hostname": hostname,
                "note": "This module validates pipeline connectivity. Replace with real detection modules.",
            },
            "findings": [
                {
                    "finding_id": f"placeholder-{scan_id[:8]}",
                    "scan_id": scan_id,
                    "module": self.name,
                    "category": "url_analysis",
                    "title": "Pipeline Connectivity Verified",
                    "description": f"The scan orchestration pipeline successfully processed {hostname}.",
                    "severity": "info",
                    "confidence": 1.0,
                    "evidence": {"target_url": target_url},
                    "recommendation": "No action required — this is a placeholder finding.",
                    "created_at": datetime.utcnow(),
                },
            ],
            "entities": [
                {
                    "entity_id": f"entity-url-{scan_id[:8]}",
                    "type": "url",
                    "value": target_url,
                    "metadata": {"source": "placeholder"},
                    "first_seen": datetime.utcnow(),
                    "last_seen": datetime.utcnow(),
                    "scan_ids": [scan_id],
                },
                {
                    "entity_id": f"entity-domain-{scan_id[:8]}",
                    "type": "domain",
                    "value": hostname,
                    "metadata": {"source": "placeholder"},
                    "first_seen": datetime.utcnow(),
                    "last_seen": datetime.utcnow(),
                    "scan_ids": [scan_id],
                },
            ],
            "relationships": [
                {
                    "relationship_id": f"rel-{scan_id[:8]}",
                    "source_entity_id": f"entity-url-{scan_id[:8]}",
                    "target_entity_id": f"entity-domain-{scan_id[:8]}",
                    "type": "resolves_to",
                    "scan_id": scan_id,
                    "confidence": 1.0,
                    "metadata": {"source": "placeholder"},
                    "created_at": datetime.utcnow(),
                },
            ],
        }
