from pydantic import BaseModel
from typing import List, Optional

class BasicScanRequest(BaseModel):
    target: str
    options: List[str]

class AdvancedScanRequest(BaseModel):
    target: str

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    
class Finding(BaseModel):
    vulnerability: str           # e.g. "SQL Injection", "XSS", "Open Ports", ...
    parameter: Optional[str]     # e.g. "id", "search", or None
    payloads: List[str] = []     

class ScanResult(BaseModel):
    scan_id: str
    target: Optional[str] = None
    findings: List[Finding] = []