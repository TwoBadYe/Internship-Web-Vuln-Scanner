# app/models.py
from pydantic import BaseModel, Field
from typing import List, Optional

class BasicScanRequest(BaseModel):
    target: str
    options: List[str] = Field(default_factory=list)

class AdvancedScanRequest(BaseModel):
    target: str

class ScanStatus(BaseModel):
    scan_id: str
    status: str

class Finding(BaseModel):
    vulnerability: str           
    parameter: Optional[str]    
    payloads: List[str] = Field(default_factory=list)

class ScanResult(BaseModel):
    scan_id: str
    target: Optional[str] = None
    findings: List[Finding] = Field(default_factory=list)
