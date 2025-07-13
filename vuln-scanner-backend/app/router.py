from fastapi import APIRouter, BackgroundTasks
from uuid import uuid4
from .models import BasicScanRequest, AdvancedScanRequest, ScanStatus, ScanResult
from .scanner import run_basic_scan, run_advanced_scan
from .store import store, get_status, get_results

router = APIRouter(prefix="/scan", tags=["scan"])

@router.post("/scan/basic", response_model=ScanStatus)
async def basic_scan(request: BasicScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid4())
    store[scan_id] = {"status": "in_progress", "results": []}
    background_tasks.add_task(run_basic_scan, scan_id, request.target, request.options)
    return {"scan_id": scan_id, "status": "in_progress"}

@router.post("/scan/advanced", response_model=ScanStatus)
async def advanced_scan(request: AdvancedScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid4())
    store[scan_id] = {"status": "in_progress", "results": []}
    background_tasks.add_task(run_advanced_scan, scan_id, request.target)
    return {"scan_id": scan_id, "status": "in_progress"}

@router.get("/scan/{scan_id}/status", response_model=ScanStatus)
async def check_status(scan_id: str):
    return get_status(scan_id)

@router.get("/scan/{scan_id}/results", response_model=ScanResult)
async def check_results(scan_id: str):
    return get_results(scan_id)