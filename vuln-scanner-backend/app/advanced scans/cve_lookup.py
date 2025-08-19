# app/scans_advanced/cve_lookup.py
SCAN_NAME = "CVE Lookup"

import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# optional backends
_HAS_VULNERS = False
_HAS_NVDLIB = False
try:
    import vulners
    _HAS_VULNERS = True
except Exception:
    _HAS_VULNERS = False

try:
    import nvdlib
    _HAS_NVDLIB = True
except Exception:
    _HAS_NVDLIB = False

# static DB path (project app/data/cve_db.json)
DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "cve_db.json"

def _load_static_db(path: Optional[str] = None) -> Dict[str, Any]:
    p = Path(path) if path else DEFAULT_DB
    if not p.exists():
        logger.debug("Static CVE DB not found at %s", p)
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        logger.exception("Failed to load static CVE DB %s: %s", p, e)
        return {}

def _vulners_lookup(product: str, version: Optional[str]) -> List[Dict[str, Any]]:
    findings = []
    key = os.environ.get("VULNERS_API_KEY")
    if not key or not _HAS_VULNERS:
        return findings
    try:
        api = vulners.Vulners(api_key=key)
        query = f"{product} {version}" if version else product
        res = api.search(query)
        # Vulners Python client structures may vary — parse conservatively
        if isinstance(res, dict):
            # attempt to find CVE-like entries
            docs = res.get("data", {}).get("documents", []) or res.get("documents") or []
            for item in docs:
                cve = item.get("id") or item.get("title") or item.get("href")
                severity = item.get("severity") or item.get("cvss") or "UNKNOWN"
                findings.append({"cve": cve, "severity": severity, "description": item.get("title", "")})
    except Exception as e:
        logger.exception("Vulners lookup failed for %s %s: %s", product, version, e)
    return findings

def _nvdlib_lookup(product: str, version: Optional[str]) -> List[Dict[str, Any]]:
    results = []
    if not _HAS_NVDLIB:
        return results
    try:
        q = product if not version else f"{product} {version}"
        cves = nvdlib.searchCVE(keyword=q)
        for c in cves:
            cve_id = getattr(c, 'id', None) or (getattr(c, 'cve', {}).get('CVE_data_meta', {}).get('ID') if hasattr(c, 'cve') else None)
            severity = None
            if hasattr(c, 'cvss'):
                try:
                    severity = getattr(c, 'cvss').get('baseScore')
                except Exception:
                    severity = None
            desc = ""
            try:
                desc = getattr(c, 'cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', '')
            except Exception:
                desc = str(c)
            results.append({"cve": cve_id, "severity": severity or "UNKNOWN", "description": desc})
    except Exception as e:
        logger.exception("nvdlib lookup failed for %s %s: %s", product, version, e)
    return results

def _match_static_db(detections: List[Dict[str, Any]], db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    db = _load_static_db(db_path)
    findings = []
    for det in detections:
        product = det.get("product")
        version = det.get("version")
        evidence = det.get("evidence", "")
        if not product:
            continue
        matched_key = None
        for k in db.keys():
            if k.lower() == product.lower():
                matched_key = k
                break
        if not matched_key:
            continue
        product_db = db[matched_key]
        candidates = []
        if isinstance(product_db, dict):
            if version and version in product_db:
                candidates.extend(product_db[version])
            if version:
                for vkey, entries in product_db.items():
                    if vkey and (version.startswith(vkey) or vkey.startswith(version)):
                        candidates.extend(entries)
            for vkey, entries in product_db.items():
                if isinstance(entries, list):
                    for e in entries:
                        if isinstance(e, dict) and 'version_range' in e:
                            candidates.append(e)
        elif isinstance(product_db, list):
            candidates.extend(product_db)
        for c in candidates:
            sev = (c.get("severity") or "").upper()
            if sev in ("HIGH", "CRITICAL"):
                findings.append({
                    "cve": c.get("cve", "UNKNOWN"),
                    "severity": sev,
                    "description": c.get("description", ""),
                    "evidence": evidence,
                    "product": matched_key,
                    "version": version
                })
    return findings

def lookup(detections: List[Dict[str, Any]], db_path: Optional[str] = None) -> List[str]:
    """
    Returns user-friendly strings (HIGH/CRITICAL CVEs only).
    Tries Vulners -> nvdlib -> static DB.
    """
    if not isinstance(detections, list):
        return []

    output_lines: List[str] = []

    # Vulners
    if _HAS_VULNERS and os.environ.get("VULNERS_API_KEY"):
        for d in detections:
            prod = d.get("product")
            ver = d.get("version")
            evidence = d.get("evidence", "")
            try:
                vulns = _vulners_lookup(prod, ver)
                for v in vulns:
                    sev = str(v.get("severity") or "").upper()
                    if sev in ("HIGH", "CRITICAL"):
                        output_lines.append(f"High CVE on {prod}/{ver or 'unknown'}: {v.get('cve')} - {v.get('description')} (evidence: {evidence})")
            except Exception as e:
                logger.exception("Vulners backend failure: %s", e)
        if output_lines:
            return output_lines

    # nvdlib
    if _HAS_NVDLIB:
        for d in detections:
            prod = d.get("product")
            ver = d.get("version")
            evidence = d.get("evidence", "")
            try:
                nv = _nvdlib_lookup(prod, ver)
                for v in nv:
                    sev = v.get("severity") or "UNKNOWN"
                    try:
                        numeric = float(sev)
                        high = numeric >= 7.0
                    except Exception:
                        high = str(sev).upper() in ("HIGH", "CRITICAL")
                    if high:
                        output_lines.append(f"High CVE on {prod}/{ver or 'unknown'}: {v.get('cve')} - {v.get('description')} (evidence: {evidence})")
            except Exception as e:
                logger.exception("nvdlib backend failure: %s", e)
        if output_lines:
            return output_lines

    # static DB fallback
    matched = _match_static_db(detections, db_path=db_path)
    for m in matched:
        output_lines.append(f"High CVE on {m.get('product')}/{m.get('version') or 'unknown'}: {m.get('cve')} - {m.get('description')} (evidence: {m.get('evidence')})")
    return output_lines

# compatibility run stub (if scan runner expects run)
async def run(target: str, client=None) -> List[str]:
    return ["CVE Lookup executed (use lookup(detections) for real results)"]
