"""
PHANTOM Entity & Relationship Models
Used for the investigation graph.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class EntityType(str, Enum):
    """Types of entities in the investigation graph."""
    URL = "url"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    CERTIFICATE = "certificate"
    NAMESERVER = "nameserver"
    REGISTRAR = "registrar"
    ASN = "asn"
    EMAIL = "email"
    ORGANIZATION = "organization"
    NETWORK = "network"
    HOSTING_PROVIDER = "hosting_provider"


class RelationshipType(str, Enum):
    """Types of relationships between entities."""
    RESOLVES_TO = "resolves_to"
    HOSTED_ON = "hosted_on"
    REGISTERED_BY = "registered_by"
    USES_NAMESERVER = "uses_nameserver"
    HAS_CERTIFICATE = "has_certificate"
    ISSUED_BY = "issued_by"
    BELONGS_TO_ASN = "belongs_to_asn"
    ASSOCIATED_WITH = "associated_with"
    REDIRECTS_TO = "redirects_to"
    SIMILAR_TO = "similar_to"
    PART_OF_NETWORK = "part_of_network"
    CONTACTED_BY = "contacted_by"


class EntityDocument(BaseModel):
    """MongoDB document schema for entities."""
    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: EntityType
    value: str = Field(..., description="Entity value (e.g., domain name, IP address)")
    metadata: dict = Field(default_factory=dict, description="Additional entity metadata")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    scan_ids: list[str] = Field(default_factory=list, description="Scans that discovered this entity")


class RelationshipDocument(BaseModel):
    """MongoDB document schema for relationships."""
    relationship_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_entity_id: str
    target_entity_id: str
    type: RelationshipType
    scan_id: str = Field(..., description="Scan that discovered this relationship")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EntityResponse(BaseModel):
    """API response model for entities."""
    entity_id: str
    type: str
    value: str
    metadata: dict
    first_seen: datetime
    last_seen: datetime
    scan_ids: list[str]


class RelationshipResponse(BaseModel):
    """API response model for relationships."""
    relationship_id: str
    source_entity_id: str
    target_entity_id: str
    type: str
    confidence: float
    metadata: dict
    scan_id: str
    created_at: datetime


class GraphResponse(BaseModel):
    """API response for the full investigation graph."""
    nodes: list[EntityResponse] = Field(default_factory=list)
    edges: list[RelationshipResponse] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict, description="Graph statistics")
