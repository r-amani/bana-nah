"""
PHANTOM Scan Orchestrator
Central coordinator that dispatches scan tasks to registered modules.
"""
import asyncio
import logging
import time
from datetime import datetime
from typing import Optional

from app.database import get_db
from app.models.scan import ScanDocument, ScanStatus, ModuleResult, ModuleStatus
from app.models.finding import FindingDocument
from app.models.entity import EntityDocument, RelationshipDocument
from app.security.url_validator import validate_url, extract_hostname, validate_resolved_ip

logger = logging.getLogger("phantom.scanner.orchestrator")


class ModuleInterface:
    """
    Base interface that all scan modules must implement.

    Each module receives the target URL and hostname,
    performs its analysis, and returns a standardized result dict.
    """

    name: str = "base_module"
    description: str = "Base module"
    version: str = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        """
        Execute the module's analysis.

        Must return a dict with:
        {
            "data": { ... module-specific results ... },
            "findings": [ FindingDocument-compatible dicts ],
            "entities": [ EntityDocument-compatible dicts ],
            "relationships": [ RelationshipDocument-compatible dicts ],
        }
        """
        raise NotImplementedError("Modules must implement execute()")


class ScanOrchestrator:
    """
    Central scan orchestrator.
    Manages module registration, scan execution, and result aggregation.
    """

    def __init__(self):
        self._modules: dict[str, ModuleInterface] = {}
        logger.info("ScanOrchestrator initialized")

    def register_module(self, module: ModuleInterface) -> None:
        """Register a scan module."""
        self._modules[module.name] = module
        logger.info("Module registered: %s (v%s) — %s", module.name, module.version, module.description)

    def unregister_module(self, name: str) -> None:
        """Unregister a scan module."""
        if name in self._modules:
            del self._modules[name]
            logger.info("Module unregistered: %s", name)

    def list_modules(self) -> list[dict]:
        """List all registered modules."""
        return [
            {"name": m.name, "description": m.description, "version": m.version}
            for m in self._modules.values()
        ]

    async def run_scan(self, target_url: str, requested_modules: Optional[list[str]] = None, request_ip: Optional[str] = None) -> dict:
        """
        Execute a full scan against the target URL.

        Steps:
        1. Validate the URL (SSRF protection)
        2. Create a scan document
        3. Run all requested modules (or all registered)
        4. Aggregate results
        5. Compute risk score
        6. Store everything in the database
        """
        start_time = time.time()

        # Step 1: Validate URL
        validated_url = validate_url(target_url)
        hostname = extract_hostname(validated_url)

        # Validate resolved IP (SSRF protection at DNS level)
        try:
            resolved_ip = validate_resolved_ip(hostname)
        except Exception as e:
            logger.warning("DNS resolution validation failed for %s: %s", hostname, e)
            resolved_ip = None

        # Step 2: Create scan document
        scan_doc = ScanDocument(
            target_url=validated_url,
            hostname=hostname,
            status=ScanStatus.RUNNING,
            request_ip=request_ip,
        )

        db = get_db()
        await db.scans.insert_one(scan_doc.model_dump())
        logger.info("Scan %s started for %s", scan_doc.scan_id, validated_url)

        # Step 3: Determine which modules to run
        if requested_modules:
            modules_to_run = {
                name: mod for name, mod in self._modules.items()
                if name in requested_modules
            }
            # Mark unavailable modules
            for req_name in requested_modules:
                if req_name not in self._modules:
                    scan_doc.module_results.append(
                        ModuleResult(
                            module=req_name,
                            status=ModuleStatus.UNAVAILABLE,
                            error=f"Module '{req_name}' is not registered",
                        ).model_dump()
                    )
        else:
            modules_to_run = dict(self._modules)

        # Step 4: Execute modules concurrently
        all_findings = []
        all_entities = []
        all_relationships = []

        if modules_to_run:
            tasks = {
                name: asyncio.create_task(
                    self._execute_module_safe(mod, validated_url, hostname, scan_doc.scan_id)
                )
                for name, mod in modules_to_run.items()
            }

            results = await asyncio.gather(*tasks.values(), return_exceptions=True)

            for (name, _), result in zip(tasks.items(), results):
                if isinstance(result, Exception):
                    module_result = ModuleResult(
                        module=name,
                        status=ModuleStatus.FAILED,
                        error=str(result),
                    )
                else:
                    module_result = result["module_result"]
                    all_findings.extend(result.get("findings", []))
                    all_entities.extend(result.get("entities", []))
                    all_relationships.extend(result.get("relationships", []))

                scan_doc.module_results.append(module_result.model_dump() if isinstance(module_result, ModuleResult) else module_result)

        # Step 5: Compute overall status
        statuses = [ModuleStatus(r.get("status", "failed") if isinstance(r, dict) else r.status) for r in scan_doc.module_results]
        if all(s == ModuleStatus.COMPLETED for s in statuses):
            scan_doc.status = ScanStatus.COMPLETED
        elif all(s in (ModuleStatus.FAILED, ModuleStatus.UNAVAILABLE) for s in statuses):
            scan_doc.status = ScanStatus.FAILED
        elif any(s == ModuleStatus.COMPLETED for s in statuses):
            scan_doc.status = ScanStatus.PARTIAL
        else:
            scan_doc.status = ScanStatus.FAILED

        # Step 6: Compute risk score (placeholder — the risk scoring module will override)
        risk_score = self._compute_basic_risk_score(all_findings)
        scan_doc.risk_score = risk_score
        scan_doc.risk_level = self._risk_level(risk_score)

        # Timing
        elapsed = (time.time() - start_time) * 1000
        scan_doc.completed_at = datetime.utcnow()
        scan_doc.duration_ms = round(elapsed, 2)
        scan_doc.summary = f"Scan completed in {elapsed:.0f}ms with {len(all_findings)} findings."

        # Step 7: Persist results
        await db.scans.update_one(
            {"scan_id": scan_doc.scan_id},
            {"$set": scan_doc.model_dump()},
        )

        # Persist findings
        if all_findings:
            await db.findings.insert_many([f if isinstance(f, dict) else f.model_dump() for f in all_findings])

        # Persist entities (upsert by type+value)
        for entity in all_entities:
            entity_dict = entity if isinstance(entity, dict) else entity.model_dump()
            await db.entities.update_one(
                {"type": entity_dict["type"], "value": entity_dict["value"]},
                {
                    "$set": {k: v for k, v in entity_dict.items() if k not in ("scan_ids",)},
                    "$addToSet": {"scan_ids": scan_doc.scan_id},
                    "$setOnInsert": {"first_seen": entity_dict.get("first_seen", datetime.utcnow())},
                },
                upsert=True,
            )

        # Persist relationships
        if all_relationships:
            await db.relationships.insert_many(
                [r if isinstance(r, dict) else r.model_dump() for r in all_relationships]
            )

        logger.info(
            "Scan %s completed — status: %s, risk: %.1f (%s), findings: %d",
            scan_doc.scan_id, scan_doc.status, risk_score, scan_doc.risk_level, len(all_findings),
        )

        return scan_doc.model_dump()

    async def _execute_module_safe(self, module: ModuleInterface, url: str, hostname: str, scan_id: str) -> dict:
        """Execute a module with timing and error handling."""
        start = time.time()
        module_result = ModuleResult(
            module=module.name,
            status=ModuleStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        try:
            result = await asyncio.wait_for(
                module.execute(url, hostname, scan_id),
                timeout=30.0,  # Per-module timeout
            )
            elapsed = (time.time() - start) * 1000
            module_result.status = ModuleStatus.COMPLETED
            module_result.completed_at = datetime.utcnow()
            module_result.duration_ms = round(elapsed, 2)
            module_result.data = result.get("data")

            return {
                "module_result": module_result,
                "findings": result.get("findings", []),
                "entities": result.get("entities", []),
                "relationships": result.get("relationships", []),
            }

        except asyncio.TimeoutError:
            module_result.status = ModuleStatus.FAILED
            module_result.error = "Module execution timed out (30s)"
            module_result.completed_at = datetime.utcnow()
            module_result.duration_ms = (time.time() - start) * 1000
            logger.warning("Module %s timed out for scan %s", module.name, scan_id)
            return {"module_result": module_result, "findings": [], "entities": [], "relationships": []}

        except Exception as e:
            module_result.status = ModuleStatus.FAILED
            module_result.error = str(e)
            module_result.completed_at = datetime.utcnow()
            module_result.duration_ms = (time.time() - start) * 1000
            logger.exception("Module %s failed for scan %s: %s", module.name, scan_id, e)
            return {"module_result": module_result, "findings": [], "entities": [], "relationships": []}

    def _compute_basic_risk_score(self, findings: list) -> float:
        """Compute a basic risk score from findings. Modules may override this."""
        if not findings:
            return 0.0

        severity_weights = {
            "critical": 25.0,
            "high": 15.0,
            "medium": 8.0,
            "low": 3.0,
            "info": 0.5,
        }

        score = 0.0
        for finding in findings:
            f = finding if isinstance(finding, dict) else finding.model_dump()
            severity = f.get("severity", "info")
            confidence = f.get("confidence", 0.5)
            weight = severity_weights.get(severity, 0.5)
            score += weight * confidence

        return min(score, 100.0)

    @staticmethod
    def _risk_level(score: float) -> str:
        """Convert numeric risk score to risk level."""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        elif score > 0:
            return "low"
        return "none"


# Global orchestrator instance
orchestrator = ScanOrchestrator()
