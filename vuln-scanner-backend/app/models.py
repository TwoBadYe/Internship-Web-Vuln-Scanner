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

class ScanResult(BaseModel):
    scan_id: str
    target: Optional[str] = None
    findings: List[str] = []