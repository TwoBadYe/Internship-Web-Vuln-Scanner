# app/scan_core.py
import asyncio
import pkgutil
import importlib
from typing import List, Dict
import httpx
from collections import defaultdict
import re
from .models import Finding
import logging
from dotenv import load_dotenv 
import os

load_dotenv()
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")
logger = logging.getLogger(__name__)

def discover_scans() -> Dict[str, object]:
    scanners = {}
    try:
        import app.scans as scans_pkg  # requires app/scans/__init__.py
    except Exception as e:
        logger.exception("Failed to import app.scans package: %s", e)
        return scanners

    for finder, name, ispkg in pkgutil.iter_modules(scans_pkg.__path__):
        try:
            module = importlib.import_module(f"app.scans.{name}")
            if hasattr(module, "SCAN_NAME") and hasattr(module, "run"):
                scanners[module.SCAN_NAME] = module
        except Exception as e:
            logger.exception("Failed to import scan module %s: %s", name, e)
    return scanners

async def run_selected_scans(target: str, selected: List[str] = None, concurrency: int = 10) -> List[str]:
    SCANNERS = discover_scans()
    modules = []
    if not selected:
        modules = list(SCANNERS.values())
    else:
        for name in selected:
            m = SCANNERS.get(name)
            if m:
                modules.append(m)

    timeout = httpx.Timeout(15.0, read=15.0)
    raw_findings: List[str] = []

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        semaphore = asyncio.Semaphore(concurrency)

        async def run_module(mod):
            async with semaphore:
                try:
                    res = await mod.run(target, client)
                    if res:
                        raw_findings.extend(res)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    raw_findings.append(f"Error running {getattr(mod, 'SCAN_NAME', mod.__name__)}: {e}")

        await asyncio.gather(*(run_module(m) for m in modules))

    return raw_findings

def group_findings(raw: List[str]) -> List[Finding]:
    groups = defaultdict(lambda: {"vulnerability": None, "parameter": None, "payloads": []})

    for line in raw:
        m = re.match(r"^(?P<vuln>[^:]+?)(?: on `|: )", line)
        vuln = m.group("vuln").strip() if m else line

        param_match = re.search(r"on `([^`]+)`", line) or re.search(r"for `([^`]+)`", line)
        param = param_match.group(1) if param_match else None

        payload_match = re.search(r"with `([^`]+)`", line) or re.search(r"payload `([^`]+)`", line)
        if payload_match:
            payload = payload_match.group(1)
        else:
            m2 = re.search(r"via (.+)$", line)
            payload = m2.group(1) if m2 else ""

        key = (vuln, param)
        entry = groups[key]
        entry["vulnerability"] = vuln
        entry["parameter"] = param
        if payload and payload not in entry["payloads"]:
            entry["payloads"].append(payload)

    return [
        Finding(vulnerability=info["vulnerability"], parameter=info["parameter"], payloads=info["payloads"])
        for info in groups.values()
    ]

# high level wrapper to be used from router (pass store)
async def run_basic_scan(scan_id: str, target: str, options: List[str], store: dict):
    selected = options or []
    raw = await run_selected_scans(target, selected)
    grouped = group_findings(raw)
    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    # store Pydantic models (they'll be serialised by FastAPI) or dicts
    store[scan_id]['results'] = [g.dict() for g in grouped]

async def run_advanced_scan(scan_id: str, target: str, store: dict) -> None:
    """
    Advanced scan orchestration:
      - fingerprint target using app.scans_advanced.fingerprint
      - lookup CVEs using app.scans_advanced.cve_lookup
      - store grouped Finding objects via existing group_findings helper
    """
    store[scan_id]['status'] = 'in_progress'
    store[scan_id]['target'] = target
    raw_findings = []

    timeout = httpx.Timeout(20.0, read=20.0)
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            # lazy import modules
            try:
                fp_mod = importlib.import_module("app.scans_advanced.fingerprint")
            except Exception as e:
                logger.exception("Failed to import fingerprint module: %s", e)
                fp_mod = None
                raw_findings.append(f"Advanced scan error: fingerprint module import failed: {e}")

            try:
                cve_mod = importlib.import_module("app.scans_advanced.cve_lookup")
            except Exception as e:
                logger.exception("Failed to import cve_lookup module: %s", e)
                cve_mod = None
                raw_findings.append(f"Advanced scan error: cve_lookup module import failed: {e}")

            # run fingerprint
            detections = []
            if fp_mod:
                try:
                    detections = await fp_mod.detect(target, client)
                    for d in detections:
                        if d.get("product") == "fetch_error":
                            raw_findings.append(f"Fingerprinting error: {d.get('evidence')}")
                        else:
                            prod = d.get("product")
                            ver = d.get("version") or "unknown"
                            ev = d.get("evidence", "")
                            raw_findings.append(f"Technology Detected: {prod}/{ver} — {ev}")
                except Exception as e:
                    logger.exception("Fingerprinting failed: %s", e)
                    raw_findings.append(f"Fingerprinting failed: {e}")

            # run cve lookup
            if cve_mod and detections:
                try:
                    cve_lines = cve_mod.lookup(detections)
                    if cve_lines:
                        raw_findings.extend(cve_lines)
                    else:
                        raw_findings.append("CVE lookup found no high-severity issues")
                except Exception as e:
                    logger.exception("CVE lookup failed: %s", e)
                    raw_findings.append(f"CVE lookup failed: {e}")

    except Exception as outer:
        logger.exception("Advanced scan top-level failure: %s", outer)
        raw_findings.append(f"Advanced scan failed: {outer}")

    # convert to Finding objects using scan_core.group_findings (make sure group_findings exists in this module)
    try:
        grouped = group_findings(raw_findings)
    except Exception as e:
        logger.exception("group_findings failed: %s", e)
        # fallback: store raw strings
        store[scan_id]['status'] = 'done'
        store[scan_id]['results'] = raw_findings
        return

    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    store[scan_id]['results'] = grouped

def available_scans():
    return list(discover_scans().keys())
