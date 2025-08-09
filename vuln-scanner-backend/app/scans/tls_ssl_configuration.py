# app/scans/tls_ssl.py
SCAN_NAME = "TLS/SSL Configuration"

import asyncio
import socket
import ssl
import datetime
from typing import List

async def run(target: str, client=None) -> List[str]:
    """
    Check TLS protocol, cipher and certificate expiry for target:443.
    Uses run_in_executor to avoid blocking the event loop.
    """
    findings: List[str] = []

    # normalize host
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    port = 443

    def sync_check():
        ctx = ssl.create_default_context()
        # For scanning we don't want verification to fail the handshake
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.version()            # e.g. "TLSv1.2"
                cipher = ssock.cipher()[0]        # cipher name
                cert = ssock.getpeercert()        # dict
        return proto, cipher, cert

    loop = asyncio.get_running_loop()
    try:
        proto, cipher, cert = await loop.run_in_executor(None, sync_check)

        # Protocol check
        if proto not in ("TLSv1.2", "TLSv1.3"):
            findings.append(f"Weak TLS protocol in use: {proto}")

        # Cipher check (simple heuristic)
        if any(bad in cipher.upper() for bad in ("RC4", "DES", "3DES")):
            findings.append(f"Weak cipher suite in use: {cipher}")

        # Certificate expiry
        not_after = cert.get("notAfter")
        if not_after:
            try:
                # Typical format: 'Jul 17 12:00:00 2025 GMT'
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            except Exception:
                try:
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
                except Exception:
                    exp = None

            if exp:
                days_left = (exp - datetime.datetime.utcnow()).days
                if days_left < 30:
                    findings.append(f"Certificate expires in {days_left} days on {exp.date()}")
    except Exception as e:
        findings.append(f"Error checking TLS/SSL on {host}:{port} - {e}")

    return findings

