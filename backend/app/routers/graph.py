"""
PHANTOM Investigation Graph Router
Provides graph data for the interactive investigation visualization.
"""
import logging
from fastapi import APIRouter, HTTPException, Query

from app.database import get_db
from app.models.entity import EntityResponse, RelationshipResponse, GraphResponse

logger = logging.getLogger("phantom.routers.graph")

router = APIRouter()


@router.get("/graph", response_model=GraphResponse, summary="Get investigation graph")
async def get_graph(
    scan_id: str = Query(default=None, description="Filter graph by scan ID"),
    hostname: str = Query(default=None, description="Filter graph by hostname"),
    max_nodes: int = Query(default=200, ge=1, le=1000, description="Maximum nodes"),
):
    """
    Retrieve the investigation graph containing entities (nodes) and relationships (edges).
    Optionally filter by scan_id or hostname.
    """
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    # Build entity query
    entity_query = {}
    if scan_id:
        entity_query["scan_ids"] = scan_id
    if hostname:
        # Find entities related to the hostname
        entity_query["$or"] = [
            {"value": hostname},
            {"type": "domain", "value": hostname},
        ]

    # Fetch entities
    entities = await db.entities.find(entity_query, {"_id": 0}).limit(max_nodes).to_list(length=max_nodes)

    if not entities:
        return GraphResponse(
            nodes=[],
            edges=[],
            metadata={"total_nodes": 0, "total_edges": 0, "filters": {"scan_id": scan_id, "hostname": hostname}},
        )

    entity_ids = [e["entity_id"] for e in entities]

    # Fetch relationships between fetched entities
    rel_query = {
        "$or": [
            {"source_entity_id": {"$in": entity_ids}},
            {"target_entity_id": {"$in": entity_ids}},
        ]
    }
    if scan_id:
        rel_query["scan_id"] = scan_id

    relationships = await db.relationships.find(rel_query, {"_id": 0}).to_list(length=5000)

    # Include entities referenced in relationships but not yet fetched
    all_ref_ids = set()
    for rel in relationships:
        all_ref_ids.add(rel["source_entity_id"])
        all_ref_ids.add(rel["target_entity_id"])
    missing_ids = all_ref_ids - set(entity_ids)

    if missing_ids:
        extra_entities = await db.entities.find(
            {"entity_id": {"$in": list(missing_ids)}}, {"_id": 0}
        ).to_list(length=len(missing_ids))
        entities.extend(extra_entities)

    return GraphResponse(
        nodes=[EntityResponse(**e) for e in entities],
        edges=[RelationshipResponse(**r) for r in relationships],
        metadata={
            "total_nodes": len(entities),
            "total_edges": len(relationships),
            "filters": {"scan_id": scan_id, "hostname": hostname},
        },
    )
