import asyncio
from typing import List
import httpx
import socket

# ========== MODULES ==========

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
    Attempts multiple directory traversal payloads on common parameters,
    checking for presence of /etc/passwd (Linux) or hosts file (Windows).
    """
    findings: List[str] = []
    base = target.rstrip('/')
    params = ["file", "path", "page", "resource", "dir"]
    # Plain and URL-encoded payloads
    raw = "../../etc/passwd"
    raw_win = "..\\..\\Windows\\system32\\drivers\\etc\\hosts"
    payloads = [
        raw,
        raw_win,
        raw.replace("../", "..%2F"),
        raw.replace("..", "%2e%2e"),
        raw_win.replace("\\", "%5C")
    ]

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for param in params:
            for payload in payloads:
                url = f"{base}/?{param}={payload}"
                try:
                    resp = await client.get(url)
                    text = resp.text.lower()
                    # Check for Linux passwd or Windows hosts signature
                    if resp.status_code == 200:
                        if "root:" in text:
                            findings.append(
                                f"Possible Linux traversal on `{param}` with `{payload}` (found /etc/passwd)"
                            )
                        elif "127.0.0.1" in text and "localhost" in text:
                            findings.append(
                                f"Possible Windows traversal on `{param}` with `{payload}` (found hosts file)"
                            )
                except Exception as e:
                    findings.append(f"Error on `{param}` with `{payload}`: {e}")

    return findings

async def check_open_ports(target: str, ports: List[int] = None) -> List[str]:
    if ports is None:
        ports = [80, 443, 8080]
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

async def check_sql_injection(target: str) -> List[str]:
    findings = []
    payloads = [
        "' OR '1'='1",
        "';",
        "'--",
        "' OR 1=1 --",
        "' AND '1'='2",
        '" OR "1"="1'
    ]
    parameters = ["id", "user", "q", "search", "page"]

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for param in parameters:
            for payload in payloads:
                try:
                    url = target.rstrip("/") + f"/?{param}={payload}"
                    response = await client.get(url)
                    if any(err in response.text.lower() for err in ["sql", "syntax", "mysql", "psql", "query"]):
                        findings.append(f"Possible SQL injection on parameter `{param}` with payload `{payload}`")
                except Exception as e:
                    findings.append(f"Error testing SQL injection on `{param}` with payload `{payload}`: {e}")
    return findings

async def check_xss(target: str) -> List[str]: #basic payload TODO : upgrade to more advanced
    findings = []
    payload = "<script>alert('xss')</script>"
    url = target.rstrip('/') + f"/?q={payload}"
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        try:
            response = await client.get(url)
            if payload in response.text:
                findings.append("Possible reflected XSS vulnerability detected")
        except Exception as e:
            findings.append(f"Error testing XSS: {e}")
    return findings

# ========== SCAN ORCHESTRATORS ==========

async def run_basic_scan(scan_id: str, target: str, options: List[str]):
    from .store import store
    tasks = []

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

    results = await asyncio.gather(*tasks)
    findings = [item for sublist in results for item in sublist]

    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    store[scan_id]['results'] = findings

async def run_advanced_scan(scan_id: str, target: str):
    from .store import store
    await asyncio.sleep(2)
    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    store[scan_id]['results'] = ['Advanced scan not yet implemented']