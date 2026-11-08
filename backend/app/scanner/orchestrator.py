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
    name: str = "base_module"
    description: str = "Base module"
    version: str = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        raise NotImplementedError("Modules must implement execute()")


class ScanOrchestrator:
    def __init__(self):
        self._modules: dict[str, ModuleInterface] = {}
        logger.info("ScanOrchestrator initialized")

    def register_module(self, module: ModuleInterface) -> None:
        self._modules[module.name] = module
        logger.info("Module registered: %s (v%s) — %s", module.name, module.version, module.description)

    def unregister_module(self, name: str) -> None:
        if name in self._modules:
            del self._modules[name]
            logger.info("Module unregistered: %s", name)

    def list_modules(self) -> list[dict]:
        return [{"name": m.name, "description": m.description, "version": m.version} for m in self._modules.values()]

    async def _run_downstream_module(
        self, mod: Optional[ModuleInterface], url: str, host: str, scan_doc: ScanDocument,
        cur_findings: list, cur_entities: list, cur_relationships: list, **kwargs
    ) -> Optional[dict]:
        if not mod:
            return None
        try:
            res = await self._execute_module_safe(mod, url, host, scan_doc.scan_id, **kwargs)
            m_res = res["module_result"]
            cur_findings.extend(res.get("findings", []))
            cur_entities.extend(res.get("entities", []))
            cur_relationships.extend(res.get("relationships", []))
            scan_doc.module_results.append(m_res.model_dump() if isinstance(m_res, ModuleResult) else m_res)
            return res
        except Exception as e:
            scan_doc.module_results.append(ModuleResult(module=mod.name, status=ModuleStatus.FAILED, error=str(e)).model_dump())
            return None

    async def run_scan(self, target_url: str, requested_modules: Optional[list[str]] = None, request_ip: Optional[str] = None) -> dict:
        start_time = time.time()
        validated_url = validate_url(target_url)
        hostname = extract_hostname(validated_url)

        try:
            resolved_ip = validate_resolved_ip(hostname)
        except Exception as e:
            logger.warning("DNS resolution validation failed for %s: %s", hostname, e)
            resolved_ip = None

        scan_doc = ScanDocument(target_url=validated_url, hostname=hostname, status=ScanStatus.RUNNING, request_ip=request_ip)
        db = get_db()
        await db.scans.insert_one(scan_doc.model_dump())
        logger.info("Scan %s started for %s", scan_doc.scan_id, validated_url)

        if requested_modules:
            modules_to_run = {name: mod for name, mod in self._modules.items() if name in requested_modules}
            for req_name in requested_modules:
                if req_name not in self._modules:
                    scan_doc.module_results.append(
                        ModuleResult(module=req_name, status=ModuleStatus.UNAVAILABLE, error=f"Module '{req_name}' is not registered").model_dump()
                    )
        else:
            modules_to_run = dict(self._modules)

        all_findings, all_entities, all_relationships = [], [], []

        if modules_to_run:
            scoring_mod = modules_to_run.pop("risk_scoring", None)
            flight_mod = modules_to_run.pop("flight_recorder", None)
            fingerprint_mod = modules_to_run.pop("attack_fingerprint", None)
            graph_mod = modules_to_run.pop("graph_enrichment", None)

            # Stage 1: Primary Detection Modules concurrently
            if modules_to_run:
                tasks = {
                    name: asyncio.create_task(self._execute_module_safe(mod, validated_url, hostname, scan_doc.scan_id, resolved_ip=resolved_ip))
                    for name, mod in modules_to_run.items()
                }
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                for (name, _), result in zip(tasks.items(), results):
                    if isinstance(result, Exception):
                        module_result = ModuleResult(module=name, status=ModuleStatus.FAILED, error=str(result))
                    else:
                        module_result = result["module_result"]
                        all_findings.extend(result.get("findings", []))
                        all_entities.extend(result.get("entities", []))
                        all_relationships.extend(result.get("relationships", []))
                    scan_doc.module_results.append(module_result.model_dump() if isinstance(module_result, ModuleResult) else module_result)

            # Stage 2: Risk Scoring
            computed_risk_score = self._compute_basic_risk_score(all_findings)
            computed_risk_level = self._risk_level(computed_risk_score)
            score_res = await self._run_downstream_module(scoring_mod, validated_url, hostname, scan_doc, all_findings, all_entities, all_relationships, findings=all_findings)
            if score_res and isinstance(score_res["module_result"].data, dict) and "risk_score" in score_res["module_result"].data:
                computed_risk_score = float(score_res["module_result"].data["risk_score"])
                computed_risk_level = score_res["module_result"].data.get("risk_level", computed_risk_level)
            scan_doc.risk_score, scan_doc.risk_level = computed_risk_score, computed_risk_level

            # Stage 3: Flight Recorder
            await self._run_downstream_module(flight_mod, validated_url, hostname, scan_doc, all_findings, all_entities, all_relationships, findings=all_findings, module_results=scan_doc.module_results, risk_score=scan_doc.risk_score, risk_level=scan_doc.risk_level)

            # Stage 4: Attack Fingerprint
            await self._run_downstream_module(fingerprint_mod, validated_url, hostname, scan_doc, all_findings, all_entities, all_relationships, findings=all_findings, entities=all_entities, relationships=all_relationships)

            # Stage 5: Graph Enrichment
            graph_res = await self._run_downstream_module(graph_mod, validated_url, hostname, scan_doc, all_findings, all_entities, all_relationships, findings=all_findings, entities=all_entities, relationships=all_relationships)
            if graph_res:
                all_entities = graph_res.get("entities", all_entities)
                all_relationships = graph_res.get("relationships", all_relationships)

        statuses = [ModuleStatus(r.get("status", "failed") if isinstance(r, dict) else r.status) for r in scan_doc.module_results]
        if all(s == ModuleStatus.COMPLETED for s in statuses):
            scan_doc.status = ScanStatus.COMPLETED
        elif all(s in (ModuleStatus.FAILED, ModuleStatus.UNAVAILABLE) for s in statuses):
            scan_doc.status = ScanStatus.FAILED
        elif any(s == ModuleStatus.COMPLETED for s in statuses):
            scan_doc.status = ScanStatus.PARTIAL
        else:
            scan_doc.status = ScanStatus.FAILED

        elapsed = (time.time() - start_time) * 1000
        scan_doc.completed_at = datetime.utcnow()
        scan_doc.duration_ms = round(elapsed, 2)
        scan_doc.summary = f"Scan completed in {elapsed:.0f}ms with {len(all_findings)} findings across {len(scan_doc.module_results)} modules."

        # Persist results
        await db.scans.update_one({"scan_id": scan_doc.scan_id}, {"$set": scan_doc.model_dump()})
        if all_findings:
            await db.findings.insert_many([f if isinstance(f, dict) else f.model_dump() for f in all_findings])
        for entity in all_entities:
            ed = entity if isinstance(entity, dict) else entity.model_dump()
            await db.entities.update_one(
                {"type": ed["type"], "value": ed["value"]},
                {
                    "$set": {k: v for k, v in ed.items() if k not in ("scan_ids", "first_seen", "_id")},
                    "$addToSet": {"scan_ids": scan_doc.scan_id},
                    "$setOnInsert": {"first_seen": ed.get("first_seen", datetime.utcnow())},
                },
                upsert=True,
            )
        if all_relationships:
            await db.relationships.insert_many([r if isinstance(r, dict) else r.model_dump() for r in all_relationships])

        logger.info("Scan %s completed — status: %s, risk: %.1f", scan_doc.scan_id, scan_doc.status, scan_doc.risk_score)
        return scan_doc.model_dump()

    async def _execute_module_safe(self, module: ModuleInterface, url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        start = time.time()
        module_result = ModuleResult(module=module.name, status=ModuleStatus.RUNNING, started_at=datetime.utcnow())

        try:
            result = await asyncio.wait_for(module.execute(url, hostname, scan_id, **kwargs), timeout=30.0)
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
        except Exception as e:
            is_timeout = isinstance(e, asyncio.TimeoutError)
            module_result.status = ModuleStatus.FAILED
            module_result.error = "Module execution timed out (30s)" if is_timeout else str(e)
            module_result.completed_at = datetime.utcnow()
            module_result.duration_ms = (time.time() - start) * 1000
            logger.warning("Module %s %s for scan %s: %s", module.name, "timed out" if is_timeout else "failed", scan_id, e)
            return {"module_result": module_result, "findings": [], "entities": [], "relationships": []}

    def _compute_basic_risk_score(self, findings: list) -> float:
        if not findings:
            return 0.0
        weights = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0, "info": 0.5}
        score = 0.0
        for f_raw in findings:
            f = f_raw if isinstance(f_raw, dict) else f_raw.model_dump()
            score += weights.get(f.get("severity", "info"), 0.5) * f.get("confidence", 0.5)
        return min(score, 100.0)

    @staticmethod
    def _risk_level(score: float) -> str:
        return "critical" if score >= 75 else ("high" if score >= 50 else ("medium" if score >= 25 else ("low" if score > 0 else "none")))


orchestrator = ScanOrchestrator()
