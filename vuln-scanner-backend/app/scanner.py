import asyncio
from typing import List
import httpx
import socket
import time
import re
from collections import defaultdict
from .models import Finding
from datetime import datetime
import ssl
# ========== MODULES ==========

async def check_robots_txt(target: str) -> List[str]:
    """
    Fetches /robots.txt and reports any Disallow or sitemap entries.
    """
    findings: List[str] = []
    # ensure we request the root path
    base = target.rstrip("/").replace("http://", "").replace("https://", "")
    url = f"http://{base}/robots.txt"
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                findings.append("Found robots.txt")
                # parse lines
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
                findings.append("robots.txt not found (status " + str(resp.status_code) + ")")
        except Exception as e:
            findings.append(f"Error fetching robots.txt: {e}")
    return findings

async def check_tls_configuration(target: str) -> List[str]:
    findings = []
    # ensure we strip “http://” or “https://”
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    port = 443

    # Create an SSL context that accepts everything
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            proto = ssock.version()  # e.g. 'TLSv1.2'
            cipher = ssock.cipher()[0]
            cert = ssock.getpeercert()

    # 1) Check protocol version
    if proto not in ("TLSv1.2", "TLSv1.3"):
        findings.append(f"Weak TLS protocol in use: {proto}")

    # 2) Check cipher strength
    if "RC4" in cipher or "DES" in cipher:
        findings.append(f"Weak cipher suite in use: {cipher}")

    # 3) Check certificate expiry
    # cert['notAfter'] like 'Jul 17 12:00:00 2025 GMT'
    exp = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    days_left = (exp - datetime.utcnow()).days
    if days_left < 30:
        findings.append(f"Certificate expires in {days_left} days on {exp.date()}")

    return findings

async def check_security_headers(target: str) -> List[str]:
    findings: List[str] = []
    url = target if target.startswith("http") else f"http://{target}"
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        try:
            response = await client.head(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
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

async def check_directory_traversal(target: str) -> List[str]:
    """
    Attempts multiple directory traversal payloads on common parameter names and paths.
    Tries to detect UNIX and Windows-specific file disclosures.
    """
    findings: List[str] = []
    
    # Define payloads
    payloads = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\win.ini",
        "../../../../../../etc/shadow",
    ]
    
    # Common endpoint patterns
    paths = [
        "/?file=",
        "/?name=",
        "/download?file=",
        "/view?name=",
        "/static/?path=",
    ]
    
    # Define known file signatures to detect successful access
    indicators = {
        "passwd": "root:x:0:0:",
        "shadow": ":$6$",  # common pattern in shadow files
        "win.ini": "[fonts]",
    }

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for base_path in paths:
            for payload in payloads:
                url = target.rstrip("/") + base_path + payload
                try:
                    response = await client.get(url)
                    body = response.text.lower()
                    for label, signature in indicators.items():
                        if signature.lower() in body:
                            findings.append(f"Possible directory traversal: fetched {label} via {url}")
                except Exception as e:
                    findings.append(f"Error during traversal test ({url}): {e}")
    
    return findings

async def check_open_ports(target: str, ports: List[int] = None) -> List[str]:
    if ports is None:
        ports = [21,22,23,25 ,80, 443, 8080]
    findings: List[str] = []
    hostname = target.split('://')[-1].split('/')[0]
    loop = asyncio.get_event_loop()

    async def probe(port: int):
        try:
            sock = socket.socket()
            sock.settimeout(1)
            await loop.sock_connect(sock, (hostname, port))
            findings.append(f"Port {port} is open")
            sock.close()
        except Exception:
            pass

    await asyncio.gather(*(probe(p) for p in ports))
    return findings

async def check_robots_txt(target: str) -> List[str]:
    """
    Fetches /robots.txt and reports any Disallow or sitemap entries.
    """
    findings: List[str] = []
    # ensure we request the root path
    base = target.rstrip("/").replace("http://", "").replace("https://", "")
    url = f"http://{base}/robots.txt"
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                findings.append("Found robots.txt")
                # parse lines
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
                findings.append("robots.txt not found (status " + str(resp.status_code) + ")")
        except Exception as e:
            findings.append(f"Error fetching robots.txt: {e}")
    return findings

async def check_clickjacking(target: str) -> List[str]:
    findings = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp = await client.get(target)
        h = {k.lower(): v for k, v in resp.headers.items()}
        # X-Frame-Options
        if 'x-frame-options' not in h:
            findings.append("Missing X-Frame-Options header")
        # CSP frame-ancestors
        csp = h.get('content-security-policy', '')
        if 'frame-ancestors' not in csp:
            findings.append("Content-Security-Policy missing frame-ancestors directive")
    return findings

async def check_sql_injection(target: str) -> List[str]:
    findings = []
    payloads = ["' OR '1'='1", "';--", "' UNION SELECT NULL--", "1' AND sleep(3)--"]
    parameters = ["id", "user", "q", "search"]

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        try:
            baseline = await client.get(target)
        except httpx.ReadTimeout:
            findings.append("Baseline request timed out")
            return findings
        except Exception as e:
            findings.append(f"Baseline request error: {e}")
            return findings

        base_len = len(baseline.text)

        for param in parameters:
            for payload in payloads:
                url = f"{target.rstrip('/')}/?{param}={payload}"
                start = time.perf_counter()
                try:
                    resp = await client.get(url)
                    delta = time.perf_counter() - start
                    body = resp.text.lower()

                    if any(err in body for err in ["sql", "syntax", "mysql", "psql"]):
                        findings.append(f"Error-based SQLi on `{param}` with `{payload}`")

                    elif "sleep" in payload and delta > 2:
                        findings.append(f"Time-based SQLi on `{param}` with `{payload}` (delay {delta:.1f}s)")

                    elif abs(len(resp.text) - base_len) / base_len > 0.2:
                        findings.append(f"Anomalous response size on `{param}` with `{payload}`")
                except httpx.ReadTimeout:
                    findings.append(f"Request timed out on `{param}` with `{payload}`")
                except Exception as e:
                    findings.append(f"Error testing SQLi on `{param}` with `{payload}`: {e}")
    return findings

async def check_xss(target: str) -> List[str]: #basic payload TODO : upgrade to more advanced
    findings: List[str] = []

    # Multiple payloads to cover different encoding/escaping scenarios
    payloads = [
        "<script>alert('xss')</script>",
        "\" onmouseover=alert('xss')",
        "'><svg onload=alert('xss')>",
        "<img src=x onerror=alert('xss')>",
        "<body onload=alert('xss')>",
        "javascript:alert('xss')"
    ]

    # Common parameters to try injecting into
    parameters = ["q", "search", "query", "input", "term"]

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for param in parameters:
            for payload in payloads:
                url = f"{target.rstrip('/')}/?{param}={payload}"
                try:
                    response = await client.get(url)
                    body = response.text.lower()

                    # Check for raw payload in the body (reflected XSS)
                    if payload.lower() in body:
                        findings.append(
                            f"Possible XSS via `{param}` with payload `{payload}` at {url}"
                        )
                    # Fuzzy match if encoding occurred
                    elif any(keyword in body for keyword in ['alert(', 'onerror', 'onload', '<script', 'svg']):
                        findings.append(
                            f"Suspicious reflection for `{param}` with payload `{payload}` at {url} — manual check recommended"
                        )
                except Exception as e:
                    findings.append(f"Error testing XSS with `{param}` and `{payload}`: {e}")

    return findings

# ========== SCAN ORCHESTRATORS ==========

async def run_basic_scan(scan_id: str, target: str, options: List[str]):
    from .store import store

    # 1) Launch selected scanners in parallel
    tasks = []
    if 'TLS/SSL Configuration' in options:
        tasks.append(check_tls_configuration(target))
    if 'HTTP Security Headers' in options:
        tasks.append(check_security_headers(target))
    if 'Directory & File Enumeration' in options:
        tasks.append(check_directory_traversal(target))
    if 'Open Ports' in options:
        tasks.append(check_open_ports(target))
    if 'SQL Injection' in options:
        tasks.append(check_sql_injection(target))
    if 'XSS' in options:
        tasks.append(check_xss(target))
    if 'Clickjacking Protection' in options:
        tasks.append(check_clickjacking(target))
    if 'Robots.txt' in options:
        tasks.append(check_robots_txt(target))
    # 2) Wait for all to finish and flatten
    raw_lists = await asyncio.gather(*tasks)
    raw_findings = [item for sublist in raw_lists for item in sublist]

    # 3) Group all raw strings into Finding objects
    #this is an abomination and needs to be burnt in holy fire but it works for now
    def group_findings(raw: List[str]) -> List[Finding]:
        groups = defaultdict(lambda: {"vulnerability": None, "parameter": None, "payloads": []})

        for line in raw:
            # 1) Identify the “type” of finding (everything up to first on ` or first colon)
            m = re.match(r"^(?P<vuln>[^:]+?)(?: on `|: )", line)
            vuln = m.group("vuln").strip() if m else line

            # 2) Extract parameter between backticks, if present
            param_match = re.search(r"on `([^`]+)`", line) or re.search(r"for `([^`]+)`", line)
            param = param_match.group(1) if param_match else None

            # 3) Extract payload after with `…` or after via 
            payload_match = re.search(r"with `([^`]+)`", line) or re.search(r"payload `([^`]+)`", line)
            if payload_match:
                payload = payload_match.group(1)
            else:
                # fallback: anything after “via ”
                m2 = re.search(r"via (.+)$", line)
                payload = m2.group(1) if m2 else ""

            # 4) Group under (vuln, param)
            key = (vuln, param)
            entry = groups[key]
            entry["vulnerability"] = vuln
            entry["parameter"] = param
            # avoid duplicates
            if payload not in entry["payloads"]:
                entry["payloads"].append(payload)

        # 5) Build Finding objects
        return [
            Finding(
            vulnerability=info["vulnerability"],
            parameter=info["parameter"],
            payloads=info["payloads"]
        )
        for info in groups.values()
        ]

    grouped = group_findings(raw_findings)

    # 4) Save results
    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    store[scan_id]['results'] = grouped

async def run_advanced_scan(scan_id: str, target: str):
    from .store import store
    await asyncio.sleep(2)
    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    store[scan_id]['results'] = ['Advanced scan not yet implemented']