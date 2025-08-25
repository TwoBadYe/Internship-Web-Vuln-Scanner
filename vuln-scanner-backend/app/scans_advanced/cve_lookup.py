# app/scans_advanced/cve_lookup.py
"""
CVE lookup module (Vulners-first, static fallback).

Provides:
 - async lookup_cves_async(detections, ...) -> List[dict]
 - async lookup_async_formatted(detections, ...) -> List[str]
 - sync lookup(detections, ...) -> List[str]
 - compatibility run(target, client) -> List[str] (stub)
"""
from __future__ import annotations
import os
import json
import logging
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from functools import lru_cache
from html import escape

logger = logging.getLogger(__name__)
SCAN_NAME = "CVE Lookup (vulners+static)"

# static DB path (app/data/cve_db.json)
DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "cve_db.json"

# Try to import vulners client library
_HAS_VULNERS = False
try:
    import vulners  # type: ignore
    _HAS_VULNERS = True
except Exception:
    _HAS_VULNERS = False

# runtime cache for external queries (product,version) -> results
_QUERY_CACHE: Dict[Tuple[str, Optional[str]], List[Dict[str, Any]]] = {}

# severity filter
DEFAULT_SEVERITY_WHITELIST = {"HIGH", "CRITICAL"}


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


def _normalize_input(detections: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if detections is None:
        return out

    if isinstance(detections, dict):
        for k, v in detections.items():
            out.append({"product": k, "version": v, "evidence": None})
        return out

    if isinstance(detections, list):
        for item in detections:
            if isinstance(item, dict):
                product = item.get("product") or item.get("name") or item.get("technology")
                version = item.get("version") or item.get("ver")
                evidence = item.get("evidence") or item.get("evidence_text") or item.get("confidence")
                out.append({"product": product, "version": version, "evidence": evidence})
            elif isinstance(item, str):
                s = item
                try:
                    left = s.split("—", 1)[0].strip()
                    if left.lower().startswith("technology detected:"):
                        left = left[len("technology detected:"):].strip()
                    if "/" in left:
                        prod, ver = left.split("/", 1)
                        out.append({"product": prod.strip(), "version": ver.strip(), "evidence": s})
                    else:
                        out.append({"product": left.strip(), "version": None, "evidence": s})
                except Exception:
                    out.append({"product": s, "version": None, "evidence": s})
            else:
                out.append({"product": str(item), "version": None, "evidence": str(item)})
    return out


async def _vulners_search_async(product: str, version: Optional[str], api_key: str) -> List[Dict[str, Any]]:
    if not _HAS_VULNERS:
        logger.debug("Vulners library not available")
        return []

    key = api_key or os.environ.get("VULNERS_API_KEY")
    if not key:
        logger.debug("VULNERS_API_KEY not set")
        return []

    cache_key = (product.lower() if product else "", version)
    if cache_key in _QUERY_CACHE:
        return _QUERY_CACHE[cache_key]

    def _sync_search():
        try:
            api = vulners.Vulners(api_key=key)
            q = f"{product} {version}" if version else product
            res = api.search(q)
            return res
        except Exception as e:
            logger.exception("vulners.search() failed for %s %s: %s", product, version, e)
            return None

    res = await asyncio.to_thread(_sync_search)
    parsed: List[Dict[str, Any]] = []

    if not res:
        _QUERY_CACHE[cache_key] = parsed
        return parsed

    try:
        if isinstance(res, dict):
            if "data" in res and isinstance(res["data"], dict) and "documents" in res["data"]:
                docs = res["data"]["documents"] or []
            elif "documents" in res:
                docs = res.get("documents", []) or []
            else:
                docs = []
                for k, v in res.items():
                    if isinstance(k, str) and k.upper().startswith("CVE-"):
                        docs.append({"id": k, **(v or {})})
                if not docs:
                    for v in res.values():
                        if isinstance(v, list):
                            docs.extend(v)
            for item in docs:
                if not item:
                    continue
                cve = item.get("id") or item.get("cve") or item.get("title") or item.get("href")
                sev = item.get("severity") or item.get("cvss") or item.get("cvss_score") or item.get("cvss3_score") or "UNKNOWN"
                title = item.get("title") or item.get("description") or ""
                href = item.get("href") or item.get("reference")
                parsed.append({"cve": cve, "severity": str(sev).upper(), "title": title, "href": href, "raw": item})
        elif isinstance(res, list):
            for item in res:
                if isinstance(item, dict):
                    parsed.append({
                        "cve": item.get("id") or item.get("cve") or item.get("title"),
                        "severity": str(item.get("severity", "UNKNOWN")).upper(),
                        "title": item.get("title") or item.get("description"),
                        "href": item.get("href"),
                        "raw": item,
                    })
    except Exception:
        logger.exception("Failed parsing vulners response for %s %s", product, version)
    _QUERY_CACHE[cache_key] = parsed
    return parsed


def _match_static_db(detections: List[Dict[str, Any]], db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    db = _load_static_db(db_path)
    if not db:
        return []

    out: List[Dict[str, Any]] = []
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
        product_entry = db[matched_key]
        candidates = []
        if isinstance(product_entry, dict):
            if version and version in product_entry:
                candidates.extend(product_entry[version] or [])
            if version:
                for vkey, entries in product_entry.items():
                    if vkey and (str(version).startswith(str(vkey)) or str(vkey).startswith(str(version))):
                        candidates.extend(entries or [])
            default = product_entry.get("default")
            if isinstance(default, list):
                candidates.extend(default)
            for vkey, entries in product_entry.items():
                if isinstance(entries, list):
                    for e in entries:
                        candidates.append(e)
        elif isinstance(product_entry, list):
            candidates.extend(product_entry)

        for c in candidates:
            if not isinstance(c, dict):
                continue
            sev = str(c.get("severity") or "").upper()
            if sev in DEFAULT_SEVERITY_WHITELIST:
                out.append({
                    "cve": c.get("cve") or c.get("id") or c.get("title"),
                    "severity": sev,
                    "description": c.get("description") or "",
                    "evidence": evidence,
                    "product": matched_key,
                    "version": version,
                })
    return out


async def lookup_cves_async(
    detections: Any,
    *,
    use_vulners: bool = True,
    vulners_api_key: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    normalized = _normalize_input(detections)
    results: List[Dict[str, Any]] = []

    if use_vulners and _HAS_VULNERS:
        key = vulners_api_key or os.environ.get("VULNERS_API_KEY")
        if key:
            for det in normalized:
                prod = det.get("product")
                ver = det.get("version")
                evidence = det.get("evidence", "")
                if not prod:
                    continue
                try:
                    found = await _vulners_search_async(prod, ver, key)
                    for f in found:
                        sev = str(f.get("severity") or "").upper()
                        if sev in DEFAULT_SEVERITY_WHITELIST:
                            results.append({
                                "product": prod,
                                "version": ver,
                                "cve": f.get("cve"),
                                "severity": sev,
                                "title": f.get("title") or "",
                                "href": f.get("href"),
                                "evidence": evidence,
                                "raw": f.get("raw", f),
                            })
                except Exception:
                    logger.exception("Vulners lookup failed for %s %s", prod, ver)

            if results:
                return results
        else:
            logger.debug("Vulners enabled but no API key found; skipping live lookup.")

    static_matches = _match_static_db(normalized, db_path=db_path)
    if static_matches:
        return static_matches

    return []


# ---------- formatting helpers ----------
def _maybe_nvd_link(cve_id: Optional[str], href: Optional[str] = None) -> Optional[str]:
    if not cve_id:
        return href
    cve = str(cve_id).strip()
    if cve.upper().startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{cve}"
    return href


def _format_cve_entry(entry: Dict[str, Any]) -> str:
    product = entry.get("product") or "unknown-product"
    version = entry.get("version") or "unknown"
    cve_id = entry.get("cve") or entry.get("id") or "UNKNOWN"
    severity = str(entry.get("severity") or "UNKNOWN").upper()
    title = entry.get("title") or entry.get("description") or ""
    evidence = entry.get("evidence") or ""
    href = entry.get("href") or (entry.get("raw") or {}).get("href") if isinstance(entry.get("raw"), dict) else None

    url = _maybe_nvd_link(cve_id, href)

    title = escape(str(title)).replace("\n", " ").strip()
    evidence = escape(str(evidence)).replace("\n", " ").strip()

    parts = []
    parts.append(f"High CVE on {product}/{version}: {cve_id} - {title} (severity: {severity})")
    if evidence:
        parts.append(f"(evidence: {evidence})")
    if url:
        parts.append(f"(url: {url})")
    return " ".join(parts)


# sync convenience wrapper that returns formatted strings
def lookup(detections: Any, db_path: Optional[str] = None) -> List[str]:
    try:
        res = asyncio.run(lookup_cves_async(detections, use_vulners=_HAS_VULNERS, vulners_api_key=os.environ.get("VULNERS_API_KEY"), db_path=db_path))
    except RuntimeError:
        loop = asyncio.get_event_loop()
        res = loop.run_until_complete(lookup_cves_async(detections, use_vulners=_HAS_VULNERS, vulners_api_key=os.environ.get("VULNERS_API_KEY"), db_path=db_path))

    formatted: List[str] = []
    for r in res:
        try:
            formatted.append(_format_cve_entry(r))
        except Exception:
            formatted.append(f"High CVE on {r.get('product')}/{r.get('version') or 'unknown'}: {r.get('cve') or 'UNKNOWN'} (severity: {r.get('severity') or 'UNKNOWN'})")
    return formatted


# convenience async wrapper returning formatted strings
async def lookup_async_formatted(detections: Any, db_path: Optional[str] = None) -> List[str]:
    res = await lookup_cves_async(detections, use_vulners=_HAS_VULNERS, vulners_api_key=os.environ.get("VULNERS_API_KEY"), db_path=db_path)
    return [_format_cve_entry(r) for r in res]


# compatibility run() stub used by older scan pipeline
async def run(target: str, client=None) -> List[str]:
    return ["CVE Lookup executed (use lookup_cves_async(detections) to get real results)"]


# alias
lookup_cves = lookup_cves_async
