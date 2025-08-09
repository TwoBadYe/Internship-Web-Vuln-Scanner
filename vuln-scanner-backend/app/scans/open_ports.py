# app/scans/open_ports.py
SCAN_NAME = "Open Ports"

import asyncio
import socket
from typing import List

DEFAULT_PORTS = [21, 22, 23, 25, 80, 443, 8080]

async def run(target: str, client=None) -> List[str]:
    findings: List[str] = []
    hostname = target.split('://')[-1].split('/')[0]

    loop = asyncio.get_running_loop()

    async def probe(port: int):
        try:
            sock = socket.socket()
            sock.setblocking(False)
            await loop.sock_connect(sock, (hostname, port))
            findings.append(f"Port {port} is open")
            sock.close()
        except Exception:
            # closed/filtered/unreachable — ignore
            pass

    await asyncio.gather(*(probe(p) for p in DEFAULT_PORTS))
    return findings
