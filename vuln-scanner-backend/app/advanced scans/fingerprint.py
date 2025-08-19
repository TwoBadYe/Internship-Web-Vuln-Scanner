# app/scans_advanced/fingerprint.py
SCAN_NAME = "Fingerprinting"

import logging
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Try to import python-Wappalyzer (optional, recommended).
try:
    from Wappalyzer import Wappalyzer, WebPage
    _HAS_WAPP = True
except Exception:
    _HAS_WAPP = False

# Fallback signatures (simple, conservative)
SIGNATURES = [
    ("WordPress", r"wp-content|wp-includes|wp-login.php", None, r"WordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("Joomla", r"Joomla!|\/templates\/", None, r"Joomla!\s*([0-9]+\.[0-9]+)"),
    ("Drupal", r"Drupal.settings|drupal.js|content=\"Drupal", None, r"Drupal\s*([0-9]+\.[0-9]+)"),
    ("Magento", r"mage\/|Magento", None, r"Magento\s*([0-9]+\.[0-9]+)"),
    ("Express", None, "x-powered-by", r"Express"),
    ("PHP", None, "x-powered-by", r"PHP\/([0-9]+\.[0-9]+)"),
    ("Apache", None, "server", r"Apache\/([0-9]+\.[0-9]+)"),
    ("Nginx", None, "server", r"nginx\/([0-9]+\.[0-9]+)"),
    ("IIS", None, "server", r"Microsoft-IIS\/([0-9]+\.[0-9]+)"),
]

async def _wapp_analyze(url: str) -> List[Dict[str, Any]]:
    """Use python-Wappalyzer if available. Return list of {product, version, evidence}"""
    try:
        # WebPage.new_from_url_async exists in some versions; otherwise use blocking call in thread (not required here)
        if hasattr(WebPage, "new_from_url_async"):
            page = await WebPage.new_from_url_async(url, verify=True)
            w = Wappalyzer.latest()
            results = w.analyze_with_versions(page) if hasattr(w, "analyze_with_versions") else w.analyze(page)
        else:
            # synchronous fallback: Wappalyzer may provide synchronous APIs
            page = WebPage.new_from_url(url)
            w = Wappalyzer.latest()
            results = w.analyze_with_versions(page) if hasattr(w, "analyze_with_versions") else w.analyze(page)

        detections = []
        if isinstance(results, dict):
            for app_name, info in results.items():
                ver = None
                if isinstance(info, dict):
                    # info may contain 'versions' or similar
                    versions = info.get("versions") or []
                    ver = versions[0] if versions else None
                detections.append({"product": app_name, "version": ver, "evidence": "Wappalyzer"})
        elif isinstance(results, (list, set)):
            for app_name in results:
                detections.append({"product": app_name, "version": None, "evidence": "Wappalyzer"})
        return detections
    except Exception as e:
        logger.exception("Wappalyzer failed: %s", e)
        return [{"product": "fetch_error", "version": None, "evidence": f"Wappalyzer error: {e}"}]

def _fallback_detect_from_response(body: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    detections = {}
    server = headers.get("server", "")
    for product, body_pat, header_name, ver_re in SIGNATURES:
        version = None
        evidence = None
        # header check
        if header_name:
            hval = headers.get(header_name)
            if hval:
                evidence = f"Header {header_name}: {hval}"
                if ver_re:
                    m = re.search(ver_re, hval, re.I)
                    if m:
                        version = m.group(1)
        # body pattern
        if not evidence and body_pat and re.search(body_pat, body, re.I):
            evidence = f"Body matched `{body_pat}`"
            if ver_re:
                m = re.search(ver_re, body, re.I)
                if m:
                    version = m.group(1)
        # server header fallback
        if not evidence and server and product.lower() in server.lower():
            evidence = f"Server header: {server}"
            if ver_re:
                m = re.search(ver_re, server, re.I)
                if m:
                    version = m.group(1)
        if evidence:
            key = product.lower()
            if key not in detections:
                detections[key] = {"product": product, "version": version, "evidence": evidence}
            else:
                if not detections[key].get("version") and version:
                    detections[key]["version"] = version

    if not detections:
        if server:
            detections["serverheader"] = {"product": "ServerHeader", "version": None, "evidence": f"Server: {server}"}
        else:
            detections["unknown"] = {"product": "Unknown", "version": None, "evidence": "No clear fingerprint found"}
    return list(detections.values())

async def detect(target: str, client) -> List[Dict[str, Any]]:
    """
    Return a list of detections: {"product","version","evidence"}.
    Uses Wappalyzer if available; otherwise fetches the URL and runs signature checks.
    """
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    if _HAS_WAPP:
        dets = await _wapp_analyze(url)
        if dets and not (len(dets) == 1 and dets[0].get("product") == "fetch_error"):
            return dets

    try:
        resp = await client.get(url, follow_redirects=True)
        body = (resp.text or "")[:200000]
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return _fallback_detect_from_response(body, headers)
    except Exception as e:
        logger.exception("Fingerprint fetch failed for %s: %s", url, e)
        return [{"product": "fetch_error", "version": None, "evidence": str(e)}]

async def run(target: str, client) -> List[str]:
    """Compatibility wrapper: returns formatted strings for scan_core grouping."""
    dets = await detect(target, client)
    findings = []
    for d in dets:
        if d.get("product") == "fetch_error":
            findings.append(f"Fingerprinting error: {d.get('evidence')}")
            continue
        prod = d.get("product")
        ver = d.get("version") or "unknown"
        ev = d.get("evidence", "")
        findings.append(f"Technology Detected: {prod}/{ver} — {ev}")
    return findings
