"""
PHANTOM Investigation Graph Enrichment Module
Synthesizes, cross-correlates, and deduplicates nodes and edges across
all previous scan modules into an evidence-backed unified investigation graph.
"""
import logging
from datetime import datetime
from typing import Optional
import uuid

from app.models.entity import EntityType, RelationshipType
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.graph_enrichment")


class GraphEnrichmentModule(ModuleInterface):
    """
    Graph Enrichment Module.
    Consolidates scan entities, harmonizes IDs, builds evidence-backed edges,
    and deduplicates the investigation graph topology.
    """

    name = "graph_enrichment"
    description = "Investigation graph topology builder and evidence-backed relationship synthesiser"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        """
        Synthesize graph elements across all modules.
        """
        logger.info("Executing graph enrichment synthesis for %s (scan %s)", hostname, scan_id)

        input_entities = kwargs.get("entities", [])
        input_relationships = kwargs.get("relationships", [])
        findings = kwargs.get("findings", [])

        # 1. Standardize and deduplicate entities
        enriched_nodes = self._standardize_nodes(target_url, hostname, scan_id, input_entities, findings)

        # 2. Harmonize and deduplicate relationships
        enriched_edges = self._harmonize_relationships(
            target_url, hostname, scan_id, input_relationships, enriched_nodes
        )

        data = {
            "hostname": hostname,
            "scan_id": scan_id,
            "total_nodes": len(enriched_nodes),
            "total_edges": len(enriched_edges),
            "node_types": self._count_types(enriched_nodes, "type"),
            "edge_types": self._count_types(enriched_edges, "type"),
        }

        return {
            "data": data,
            "findings": [],  # Enrichment generates graph topology rather than new threats
            "entities": enriched_nodes,
            "relationships": enriched_edges,
        }

    def _standardize_nodes(
        self, target_url: str, hostname: str, scan_id: str, raw_entities: list[dict], findings: list[dict]
    ) -> list[dict]:
        """Ensures consistent deterministic entity IDs and metadata."""
        node_map = {}

        # 1. Base URL Node
        url_id = f"url:{target_url}"
        node_map[url_id] = {
            "entity_id": url_id,
            "type": EntityType.URL.value,
            "value": target_url,
            "metadata": {"hostname": hostname, "role": "target_url"},
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "scan_ids": [scan_id],
        }

        # 2. Base Domain Node
        dom_id = f"domain:{hostname}"
        node_map[dom_id] = {
            "entity_id": dom_id,
            "type": EntityType.DOMAIN.value,
            "value": hostname,
            "metadata": {"role": "target_domain", "findings_count": len(findings)},
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "scan_ids": [scan_id],
        }

        # 3. Process all incoming raw entities
        for ent in raw_entities:
            e = ent if isinstance(ent, dict) else ent.model_dump()
            etype = e.get("type")
            evalue = e.get("value")
            if not evalue:
                continue

            # Deterministic ID based on type and value
            cid = f"{etype}:{evalue}"
            if cid in node_map:
                # Merge scan IDs and metadata
                existing = node_map[cid]
                if scan_id not in existing["scan_ids"]:
                    existing["scan_ids"].append(scan_id)
                existing["metadata"].update(e.get("metadata", {}))
                existing["last_seen"] = datetime.utcnow()
            else:
                node_map[cid] = {
                    "entity_id": cid,
                    "type": etype,
                    "value": evalue,
                    "metadata": e.get("metadata", {}),
                    "first_seen": e.get("first_seen", datetime.utcnow()),
                    "last_seen": datetime.utcnow(),
                    "scan_ids": [scan_id],
                }

        return list(node_map.values())

    def _harmonize_relationships(
        self, target_url: str, hostname: str, scan_id: str, raw_relationships: list[dict], nodes: list[dict]
    ) -> list[dict]:
        """Deduplicates relationships and maps endpoints to standardized node IDs."""
        node_ids = {n["entity_id"] for n in nodes}
        edge_map = {}

        # 1. Ensure URL -> Domain base relationship exists
        url_id = f"url:{target_url}"
        dom_id = f"domain:{hostname}"
        base_edge_key = f"{url_id}|{dom_id}|hosted_on"
        edge_map[base_edge_key] = {
            "relationship_id": str(uuid.uuid4()),
            "source_entity_id": url_id,
            "target_entity_id": dom_id,
            "type": RelationshipType.HOSTED_ON.value,
            "scan_id": scan_id,
            "confidence": 1.0,
            "metadata": {
                "evidence": f"URL hostname parsed directly from target submission {target_url}",
                "timestamp": datetime.utcnow().isoformat(),
            },
            "created_at": datetime.utcnow(),
        }

        # 2. Process incoming relationships
        for rel in raw_relationships:
            r = rel if isinstance(rel, dict) else rel.model_dump()
            src = r.get("source_entity_id", "")
            tgt = r.get("target_entity_id", "")
            rtype = r.get("type", "")

            # Normalize source/target ID formats if needed
            norm_src = self._normalize_ref(src, node_ids)
            norm_tgt = self._normalize_ref(tgt, node_ids)

            edge_key = f"{norm_src}|{norm_tgt}|{rtype}"
            if edge_key not in edge_map:
                edge_map[edge_key] = {
                    "relationship_id": r.get("relationship_id") or str(uuid.uuid4()),
                    "source_entity_id": norm_src,
                    "target_entity_id": norm_tgt,
                    "type": rtype,
                    "scan_id": scan_id,
                    "confidence": float(r.get("confidence", 1.0)),
                    "metadata": r.get("metadata", {}),
                    "created_at": r.get("created_at", datetime.utcnow()),
                }

        return list(edge_map.values())

    def _normalize_ref(self, ref: str, available_node_ids: set[str]) -> str:
        """Find matching node ID with prefix fallback."""
        if ref in available_node_ids:
            return ref
        for prefix in ("domain:", "ip:", "cert:", "url:", "nameserver:", "organization:"):
            candidate = f"{prefix}{ref}"
            if candidate in available_node_ids:
                return candidate
        return ref

    def _count_types(self, items: list[dict], field: str) -> dict:
        """Helper to count occurrences of a field."""
        counts = {}
        for item in items:
            val = str(item.get(field, "unknown"))
            counts[val] = counts.get(val, 0) + 1
        return counts
