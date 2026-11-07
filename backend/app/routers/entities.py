"""
PHANTOM Entities Router
Endpoints for entity relationship queries.
"""
import logging
from fastapi import APIRouter, HTTPException

from app.database import get_db
from app.models.entity import EntityResponse, RelationshipResponse

logger = logging.getLogger("phantom.routers.entities")

router = APIRouter()


@router.get("/entities/{entity_id}/relationships", summary="Get entity relationships")
async def get_entity_relationships(entity_id: str):
    """Retrieve all relationships for an entity (both as source and target)."""
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    # Verify entity exists
    entity = await db.entities.find_one({"entity_id": entity_id}, {"_id": 0})
    if not entity:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found")

    # Find relationships where entity is source or target
    relationships = await db.relationships.find(
        {"$or": [{"source_entity_id": entity_id}, {"target_entity_id": entity_id}]},
        {"_id": 0},
    ).to_list(length=500)

    # Collect related entity IDs
    related_ids = set()
    for rel in relationships:
        related_ids.add(rel["source_entity_id"])
        related_ids.add(rel["target_entity_id"])
    related_ids.discard(entity_id)

    # Fetch related entities
    related_entities = await db.entities.find(
        {"entity_id": {"$in": list(related_ids)}}, {"_id": 0}
    ).to_list(length=500)

    return {
        "entity": EntityResponse(**entity),
        "relationships": [RelationshipResponse(**r) for r in relationships],
        "related_entities": [EntityResponse(**e) for e in related_entities],
    }
