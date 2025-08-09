# app/scans/sql_injection.py
SCAN_NAME = "SQL Injection"

import time
import httpx
from typing import List

PAYLOADS = ["' OR '1'='1", "';--", "' UNION SELECT NULL--", "1' AND sleep(3)--"]
PARAMETERS = ["id", "user", "q", "search"]

async def run(target: str, client: httpx.AsyncClient) -> List[str]:
    findings: List[str] = []
    base = target.rstrip('/')

    try:
        baseline = await client.get(target)
        base_len = len(baseline.text)
    except Exception:
        base_len = None

    for param in PARAMETERS:
        for payload in PAYLOADS:
            url = f"{base}/?{param}={payload}"
            start = time.perf_counter()
            try:
                resp = await client.get(url)
                delta = time.perf_counter() - start
                body = resp.text.lower()
                if any(err in body for err in ["sql", "syntax", "mysql", "psql"]):
                    findings.append(f"Error-based SQLi on `{param}` with `{payload}`")
                elif "sleep" in payload and delta > 2:
                    findings.append(f"Time-based SQLi on `{param}` with `{payload}` (delay {delta:.1f}s)")
                elif base_len and abs(len(resp.text) - base_len) / base_len > 0.2:
                    findings.append(f"Anomalous response size on `{param}` with `{payload}`")
            except Exception as e:
                findings.append(f"Error testing SQLi on `{param}` with `{payload}`: {e}")
    return findings
