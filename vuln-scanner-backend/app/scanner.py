import asyncio
from typing import List
import httpx
import socket

async def check_security_headers(target: str) -> List[str]:
    """
    Performs a HEAD request and checks for common security headers.
    Returns a list of strings describing missing or misconfigured headers.
    """
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
    Attempts a simple directory traversal payload and checks response content.
    """
    findings: List[str] = []
    payload = "../../etc/passwd"
    url = target.rstrip('/') + f"/{payload}"
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        try:
            response = await client.get(url)
            if response.status_code == 200 and 'root:' in response.text:
                findings.append("Possible directory traversal: fetched /etc/passwd contents")
        except Exception as e:
            findings.append(f"Error testing directory traversal: {e}")
    return findings

async def check_open_ports(target: str, ports: List[int] = None) -> List[str]:
    """
    Checks if common ports are open on the target host.
    """
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
    """
    Placeholder for SQL injection test logic.
    """
    return ["SQL injection test not implemented"]

async def run_basic_scan(scan_id: str, target: str, options: List[str]):
    """
    Orchestrates basic scan by running selected modules concurrently.
    Updates the store for the given scan_id.
    """
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

    results = await asyncio.gather(*tasks)
    findings = [item for sublist in results for item in sublist]

    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    store[scan_id]['results'] = findings

async def run_advanced_scan(scan_id: str, target: str):
    """
    Placeholder for advanced scan logic (fingerprinting + CVE lookup).
    """
    from .store import store
    await asyncio.sleep(2)
    store[scan_id]['status'] = 'done'
    store[scan_id]['target'] = target
    store[scan_id]['results'] = ['Advanced scan not yet implemented']
