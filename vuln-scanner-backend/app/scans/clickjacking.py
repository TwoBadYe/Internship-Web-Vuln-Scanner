# app/scans/clickjacking.py
SCAN_NAME = "Clickjacking Protection"

import httpx
from typing import List

async def run(target: str, client: httpx.AsyncClient) -> List[str]:
    findings: List[str] = []
    url = target if target.startswith("http") else f"http://{target}"
    try:
        resp = await client.get(url)
        h = {k.lower(): v for k, v in resp.headers.items()}
        if 'x-frame-options' not in h:
            findings.append("Missing X-Frame-Options header")
        csp = h.get('content-security-policy', '')
        if 'frame-ancestors' not in csp:
            findings.append("Content-Security-Policy missing frame-ancestors directive")
    except Exception as e:
        findings.append(f"Error checking clickjacking on {url}: {e}")
    return findings
