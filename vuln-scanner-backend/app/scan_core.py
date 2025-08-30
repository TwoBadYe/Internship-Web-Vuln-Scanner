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
        import app.scans as scans_pkg  
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
        # 1) Identify vulnerability name and the "rest" of the line after the separator
        m = re.match(r"^(?P<vuln>[^:]+?)(?: on `|: )", line)
        if m:
            vuln = m.group("vuln").strip()
            rest = line[m.end():].strip()
        else:
            # fallback: split once on first ':' or keep whole line as vuln if none
            if ":" in line:
                vuln, rest = line.split(":", 1)
                vuln = vuln.strip()
                rest = rest.strip()
            else:
                vuln = line.strip()
                rest = ""

        # 2) Extract parameter between backticks, if present
        param_match = re.search(r"on `([^`]+)`", line) or re.search(r"for `([^`]+)`", line)
        param = param_match.group(1) if param_match else None

        # 3) Extract payload: try explicit patterns, then fallback to the rest
        payload = ""
        payload_match = re.search(r"with `([^`]+)`", line) or re.search(r"payload `([^`]+)`", line)
        if payload_match:
            payload = payload_match.group(1)
        else:
            m2 = re.search(r"via (.+)$", line)
            if m2:
                payload = m2.group(1).strip()
            else:
                # last-resort: use what's after the vuln separator, if any
                payload = rest

        # 4) Group under (vuln, param)
        key = (vuln, param)
        entry = groups[key]
        entry["vulnerability"] = vuln
        entry["parameter"] = param
        # avoid empty strings and duplicates
        if payload and payload not in entry["payloads"]:
            entry["payloads"].append(payload)

    # 5) Build Finding objects
    return [
        Finding(
            vulnerability=info["vulnerability"],
            parameter=info["parameter"],
            payloads=info["payloads"]
        )
        for info in groups.values()
    ]

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
      - Uses app.scans_advanced.fingerprint.detect to get structured detections
      - Uses app.scans_advanced.cve_lookup.lookup_async_formatted to obtain friendly CVE strings
      - Combines fingerprint formatted strings + CVE strings and stores results
    """
    raw_findings: List[str] = []
    try:
        # dynamic import of advanced scanners (optional)
        try:
            fp_mod = importlib.import_module("app.scans_advanced.fingerprint")
            logger.debug("Imported fingerprint module: %s", fp_mod)
        except Exception as e:
            fp_mod = None
            logger.exception("Failed to import fingerprint module: %s", e)

        try:
            cve_mod = importlib.import_module("app.scans_advanced.cve_lookup")
            logger.debug("Imported cve_lookup module: %s", cve_mod)
        except Exception as e:
            cve_mod = None
            logger.exception("Failed to import cve_lookup module: %s", e)

        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            # 1) Fingerprint (structured)
            detections = []
            if fp_mod and hasattr(fp_mod, "detect"):
                try:
                    detections = await fp_mod.detect(target, client)
                    # Add human friendly fingerprint strings too
                    if hasattr(fp_mod, "run"):
                        try:
                            fp_strings = await fp_mod.run(target, client)
                            raw_findings.extend(fp_strings)
                        except Exception as e:
                            logger.exception("fingerprint.run() failed: %s", e)
                    else:
                        # fallback: format structured detections
                        for d in detections:
                            prod = d.get("product")
                            ver = d.get("version") or "unknown"
                            ev = d.get("evidence") or ""
                            raw_findings.append(f"Technology Detected: {prod}/{ver} via {ev}")
                except Exception as e:
                    logger.exception("Fingerprint detect failed: %s", e)
                    raw_findings.append(f"Fingerprinting error: {e}")

            # 2) CVE lookup (formatted strings)
            if cve_mod and hasattr(cve_mod, "lookup_async_formatted"):
                try:
                    cve_strings = await cve_mod.lookup_async_formatted(detections)
                    if cve_strings:
                        raw_findings.extend(cve_strings)
                    else:
                        # If lookup found nothing, optionally add a polite note
                        raw_findings.append("CVE lookup: no high/critical matches found")
                except Exception as e:
                    logger.exception("CVE lookup failed: %s", e)
                    raw_findings.append(f"CVE lookup failed: {e}")
            else:
                # no CVE module available
                raw_findings.append("CVE lookup not available (module missing)")

    except Exception as exc:
        logger.exception("Advanced scan failed: %s", exc)
        raw_findings.append(f"Advanced scan failure: {exc}")

    # group and store results
    grouped = group_findings(raw_findings)
    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    store[scan_id]['results'] = grouped

def available_scans():
    return list(discover_scans().keys())
