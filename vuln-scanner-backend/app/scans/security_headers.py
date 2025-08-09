# app/scans/security_headers.py
SCAN_NAME = "HTTP Security Headers"

import httpx
from typing import List

async def run(target: str, client: httpx.AsyncClient) -> List[str]:
    findings: List[str] = []
    url = target if target.startswith("http") else f"http://{target}"
    try:
        resp = await client.head(url, follow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        required = {
            'x-frame-options': 'deny or sameorigin',
            'x-content-type-options': 'nosniff',
            'strict-transport-security': 'max-age',
            'content-security-policy': 'policy defined',
            'referrer-policy': 'no-referrer or strict-origin'
        }
        for name, desc in required.items():
            if name not in headers:
                findings.append(f"Missing header {name}: should have {desc}")
    except Exception as e:
        findings.append(f"Error fetching headers from {url}: {e}")
    return findings
