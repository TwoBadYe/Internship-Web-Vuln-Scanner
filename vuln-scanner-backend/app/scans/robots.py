# app/scans/robots.py
SCAN_NAME = "Robots.txt"

import httpx
from typing import List

async def run(target: str, client: httpx.AsyncClient) -> List[str]:
    findings: List[str] = []
    base = target.rstrip("/").replace("http://", "").replace("https://", "")
    url = f"http://{base}/robots.txt"
    try:
        resp = await client.get(url)
        if resp.status_code == 200:
            findings.append("Found robots.txt")
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("disallow:"):
                    path = line.split(":",1)[1].strip()
                    findings.append(f"Robots disallow: {path}")
                elif line.lower().startswith("sitemap:"):
                    sitemap = line.split(":",1)[1].strip()
                    findings.append(f"Sitemap entry: {sitemap}")
        else:
            findings.append(f"robots.txt not found (status {resp.status_code})")
    except Exception as e:
        findings.append(f"Error fetching robots.txt: {e}")
    return findings
