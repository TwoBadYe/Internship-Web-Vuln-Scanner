# app/scans/xss.py
SCAN_NAME = "XSS"

import httpx
from typing import List

PAYLOADS = [
    "<script>alert('xss')</script>",
    "\" onmouseover=alert('xss')",
    "'><svg onload=alert('xss')>",
    "<img src=x onerror=alert('xss')>",
    "<body onload=alert('xss')>",
    "javascript:alert('xss')"
]

PARAMETERS = ["q", "search", "query", "input", "term"]

async def run(target: str, client: httpx.AsyncClient) -> List[str]:
    findings: List[str] = []
    base = target.rstrip('/')
    for param in PARAMETERS:
        for payload in PAYLOADS:
            url = f"{base}/?{param}={payload}"
            try:
                resp = await client.get(url)
                body = resp.text.lower()
                if payload.lower() in body:
                    findings.append(f"XSS reflection on `{param}` with `{payload}` at {url}")
                elif any(k in body for k in ['alert(', 'onerror', 'onload', '<script', 'svg']):
                    findings.append(f"Suspicious reflection for `{param}` with payload `{payload}` at {url} — manual check recommended")
            except Exception as e:
                findings.append(f"Error testing XSS on `{param}` with `{payload}`: {e}")
    return findings
