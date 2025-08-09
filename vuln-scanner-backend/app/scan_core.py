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
    try:
        await asyncio.sleep(2)
        store[scan_id]['status'] = 'done'
        store[scan_id]['target'] = target
        store[scan_id]['results'] = [{"vulnerability": "Advanced scan", "parameter": None, "payloads": ["Not implemented"]}]
    except Exception as exc:
        store[scan_id]['status'] = 'done'
        store[scan_id]['target'] = target
        store[scan_id]['results'] = [f"Advanced scan failed: {exc}"]

def available_scans():
    return list(discover_scans().keys())
