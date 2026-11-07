"""
PHANTOM Investigation Graph Router
Provides graph data for interactive threat investigation visualization.
Dynamically builds evidence-backed nodes and relationships with rich explanations and filtering.
"""
from datetime import datetime
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from app.database import get_db
from app.models.entity import EntityResponse, RelationshipResponse, GraphResponse

logger = logging.getLogger("phantom.routers.graph")

router = APIRouter()


@router.get("/graph", response_model=GraphResponse, summary="Get investigation graph")
async def get_graph(
    scan_id: Optional[str] = Query(default=None, description="Filter graph by scan ID"),
    hostname: Optional[str] = Query(default=None, description="Filter graph by domain or hostname"),
    entity_type: Optional[str] = Query(default=None, description="Filter by entity type (e.g. domain, ip_address, certificate)"),
    relationship_type: Optional[str] = Query(default=None, description="Filter by relationship type"),
    start_date: Optional[str] = Query(default=None, description="Start date ISO string"),
    end_date: Optional[str] = Query(default=None, description="End date ISO string"),
    max_nodes: int = Query(default=300, ge=1, le=1000, description="Maximum nodes"),
):
    """
    Retrieve the investigation graph containing nodes (entities) and edges (relationships).
    Includes rich relationship explanations, evidence citations, association confidence, and timestamps.
    """
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    # Safely unpack params for both FastAPI and direct Python calls
    s_id = scan_id if isinstance(scan_id, str) else None
    h_name = hostname if isinstance(hostname, str) else None
    e_type = entity_type if isinstance(entity_type, str) else None
    r_type = relationship_type if isinstance(relationship_type, str) else None
    s_date = start_date if isinstance(start_date, str) else None
    e_date = end_date if isinstance(end_date, str) else None
    node_limit = max_nodes if isinstance(max_nodes, int) else 300

    # Build entity query
    entity_query = {}
    if s_id:
        entity_query["scan_ids"] = s_id
    if h_name:
        entity_query["$or"] = [
            {"value": h_name},
            {"type": "domain", "value": h_name},
            {"metadata.hostname": h_name},
        ]
    if e_type:
        entity_query["type"] = e_type

    # Date range filters on first_seen / last_seen
    date_filter = {}
    if s_date:
        try:
            date_filter["$gte"] = datetime.fromisoformat(s_date)
        except ValueError:
            pass
    if e_date:
        try:
            date_filter["$lte"] = datetime.fromisoformat(e_date)
        except ValueError:
            pass
    if date_filter:
        entity_query["last_seen"] = date_filter

    # Fetch entities
    entities = await db.entities.find(entity_query, {"_id": 0}).limit(node_limit).to_list(length=node_limit)

    if not entities:
        return GraphResponse(
            nodes=[],
            edges=[],
            metadata={
                "total_nodes": 0,
                "total_edges": 0,
                "filters": {
                    "scan_id": s_id,
                    "hostname": h_name,
                    "entity_type": e_type,
                    "relationship_type": r_type,
                },
            },
        )

    entity_ids = [e["entity_id"] for e in entities]

    # Fetch relationships connecting these entities
    rel_query = {
        "$or": [
            {"source_entity_id": {"$in": entity_ids}},
            {"target_entity_id": {"$in": entity_ids}},
        ]
    }
    if s_id:
        rel_query["scan_id"] = s_id
    if r_type:
        rel_query["type"] = r_type

    relationships = await db.relationships.find(rel_query, {"_id": 0}).to_list(length=2000)

    # Include referenced target/source entities not yet in our list
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

    # Format nodes and edges with explanations and evidence
    formatted_nodes = [EntityResponse(**e) for e in entities]
    formatted_edges = [RelationshipResponse(**r) for r in relationships]

    # Calculate graph summary metrics
    edge_types = {}
    for r in relationships:
        t = r.get("type", "unknown")
        edge_types[t] = edge_types.get(t, 0) + 1

    return GraphResponse(
        nodes=formatted_nodes,
        edges=formatted_edges,
        metadata={
            "total_nodes": len(formatted_nodes),
            "total_edges": len(formatted_edges),
            "edge_types": edge_types,
            "filters": {
                "scan_id": s_id,
                "hostname": h_name,
                "entity_type": e_type,
                "relationship_type": r_type,
            },
        },
    )
