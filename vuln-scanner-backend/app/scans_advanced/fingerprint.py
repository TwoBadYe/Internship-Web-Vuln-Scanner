# app/scans_advanced/fingerprint.py
"""
Async fingerprinting module.

Exports:
 - SCAN_NAME (str)
 - async detect(target, client=None) -> List[dict]   # structured detections
 - async run(target, client=None) -> List[str]      # compatibility: formatted strings
 - async fingerprint(...) (alias for detect)
"""

from typing import List, Dict, Any, Optional
import re
import logging
import asyncio
import httpx

logger = logging.getLogger(__name__)
SCAN_NAME = "Fingerprinting (improved)"

# Optional Wappalyzer support (best-effort)
try:
    from Wappalyzer import Wappalyzer, WebPage  # note: may vary by package version
    _HAS_WAPP = True
except Exception:
    _HAS_WAPP = False

# Simple in-memory cache to avoid repeated network calls during dev runs
_cache: Dict[str, List[Dict[str, Any]]] = {}

# Signature tuples: (product, body_pattern, header_name, version_regex)
SIGNATURES = [
    ("WordPress", r"wp-content|wp-includes|wp-login.php", None, r"WordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Joomla", r"Joomla!|/templates/", None, r"Joomla!\s*([0-9]+\.[0-9]+)"),
    ("Drupal", r"Drupal.settings|drupal.js|content=\"Drupal", None, r"Drupal\s*([0-9]+\.[0-9]+)"),
    ("Magento", r"mage/|Magento", None, r"Magento\s*([0-9]+\.[0-9]+)"),
    ("Express", None, "x-powered-by", r"Express"),
    ("PHP", None, "x-powered-by", r"PHP\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Apache", None, "server", r"Apache\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Nginx", None, "server", r"nginx\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("IIS", None, "server", r"Microsoft-IIS\/([0-9]+\.[0-9]+)"),
]

async def _wapp_analyze(url: str, client: Optional[httpx.AsyncClient]) -> List[Dict[str, Any]]:
    """Try Wappalyzer. Always return a list of detection dicts or empty list."""
    if not _HAS_WAPP:
        return []
    try:
        # Use async webpage fetch if present; otherwise fall back to thread-safe sync call
        if hasattr(WebPage, "new_from_url_async"):
            page = await WebPage.new_from_url_async(url, verify=False)
            w = Wappalyzer.latest()
            results = w.analyze_with_versions(page) if hasattr(w, "analyze_with_versions") else w.analyze(page)
        else:
            # fallback to a thread call to avoid blocking event loop
            def sync_fetch():
                page = WebPage.new_from_url(url)
                w = Wappalyzer.latest()
                return w.analyze_with_versions(page) if hasattr(w, "analyze_with_versions") else w.analyze(page)
            results = await asyncio.to_thread(sync_fetch)

        detections: List[Dict[str, Any]] = []
        # results could be dict mapping app->info or list of names
        if isinstance(results, dict):
            for app_name, info in results.items():
                version = None
                if isinstance(info, dict):
                    versions = info.get("versions") or []
                    if versions:
                        version = versions[0]
                detections.append({"product": app_name, "version": version, "evidence": "Wappalyzer", "confidence": 95})
        elif isinstance(results, (list, set)):
            for name in results:
                detections.append({"product": name, "version": None, "evidence": "Wappalyzer", "confidence": 85})
        return detections
    except Exception as e:
        logger.exception("Wappalyzer analysis failed: %s", e)
        return [{"product": "wapp_error", "version": None, "evidence": f"Wappalyzer error: {e}", "confidence": 0}]

def _normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in (headers or {}).items()}

def _match_version(pattern: Optional[str], text: str) -> Optional[str]:
    if not pattern or not text:
        return None
    m = re.search(pattern, text, re.I)
    if not m:
        return None
    # prefer first capturing group if present
    return m.group(1) if m.groups() else m.group(0)

def _fallback_detect_from_response(body: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Improved fallback fingerprinting:
      - Header-based detection requires either version-regex match OR the product name present in header.
      - Body pattern detection used if header-based not decisive.
      - Server header considered only when it contains product name.
      - Returns list of dicts with product, version, evidence, confidence.
    """
    detections: Dict[str, Dict[str, Any]] = {}
    server = headers.get("server", "")

    for product, body_pat, header_name, ver_re in SIGNATURES:
        version = None
        evidence = None
        confidence = 0

        # HEADER-BASED: only accept when header value either matches ver_re or contains product name
        if header_name:
            hval = headers.get(header_name, "")
            if hval:
                # try strong version regex first
                v = _match_version(ver_re, hval) if ver_re else None
                if v:
                    version = v
                    evidence = f"Header {header_name}: {hval}"
                    confidence = 90
                else:
                    # fallback to presence of product name in header value
                    if product.lower() in hval.lower():
                        evidence = f"Header {header_name}: {hval}"
                        confidence = 70
                        # attempt to extract version if generic regex exists
                        if ver_re:
                            mv = _match_version(ver_re, hval)
                            if mv:
                                version = mv
                                confidence = 90

        # BODY-BASED: only if not matched via header
        if not evidence and body_pat:
            if re.search(body_pat, body, re.I):
                evidence = f"Body matched `{body_pat}`"
                confidence = 60
                if ver_re:
                    v = _match_version(ver_re, body)
                    if v:
                        version = v
                        confidence = 80

        # SERVER header fallback: only if product name appears in server header
        if not evidence and server and product.lower() in server.lower():
            evidence = f"Server header: {server}"
            confidence = 65
            if ver_re:
                v = _match_version(ver_re, server)
                if v:
                    version = v
                    confidence = 90

        if evidence:
            key = product.lower()
            existing = detections.get(key)
            if not existing:
                detections[key] = {"product": product, "version": version, "evidence": evidence, "confidence": confidence}
            else:
                # merge: prefer detection with version and/or higher confidence
                if not existing.get("version") and version:
                    existing["version"] = version
                if confidence > existing.get("confidence", 0):
                    existing["evidence"] = evidence
                    existing["confidence"] = confidence

    # If nothing detected, report minimal server header fallback or Unknown
    if not detections:
        if server:
            detections["serverheader"] = {"product": "ServerHeader", "version": None, "evidence": f"Server: {server}", "confidence": 40}
        else:
            detections["unknown"] = {"product": "Unknown", "version": None, "evidence": "No clear fingerprint found", "confidence": 10}

    return list(detections.values())

async def detect(target: str, client: Optional[httpx.AsyncClient] = None, use_cache: bool = True) -> List[Dict[str, Any]]:
    """
    Main async fingerprint function. Returns structured detections.
    - target: URL or host.
    - client: optional httpx.AsyncClient. If None, one will be created and closed.
    - use_cache: when True, caches by exact URL for lifetime of process.
    """
    # canonicalize url
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    if use_cache and url in _cache:
        return _cache[url]

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=20.0, verify=False)
        close_client = True

    try:
        # prefer Wappalyzer when available (best accuracy)
        if _HAS_WAPP:
            wres = await _wapp_analyze(url, client)
            # honor Wappalyzer if meaningful
            if wres and not (len(wres) == 1 and wres[0].get("product") == "wapp_error"):
                # store and return normalized wappalyzer outputs (confidence already set)
                _cache[url] = wres
                return wres

        # fetch page
        resp = await client.get(url, follow_redirects=True)
        body = (resp.text or "")[:200000]
        headers = _normalize_headers(resp.headers or {})
        dets = _fallback_detect_from_response(body, headers)
        if use_cache:
            _cache[url] = dets
        return dets
    except Exception as exc:
        logger.exception("Fingerprint fetch failed for %s: %s", url, exc)
        result = [{"product": "fetch_error", "version": None, "evidence": str(exc), "confidence": 0}]
        if use_cache:
            _cache[url] = result
        return result
    finally:
        if close_client:
            await client.aclose()

# compatibility alias
async def fingerprint(target: str, client: Optional[httpx.AsyncClient] = None):
    return await detect(target, client)

# compatibility run() expected by scan_core: returns list of formatted strings
async def run(target: str, client: Optional[httpx.AsyncClient] = None) -> List[str]:
    dets = await detect(target, client)
    out: List[str] = []
    for d in dets:
        if d.get("product") == "fetch_error":
            out.append(f"Fingerprinting error: {d.get('evidence')}")
            continue
        prod = d.get("product")
        ver = d.get("version") or "unknown"
        ev = d.get("evidence", "")
        conf = d.get("confidence", 0)
        out.append(f"Technology Detected: {prod}/{ver} via {ev} (confidence={conf})")
    return out
