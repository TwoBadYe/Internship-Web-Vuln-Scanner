# app/router.py
from fastapi import APIRouter, BackgroundTasks
from uuid import uuid4
from .models import BasicScanRequest, AdvancedScanRequest, ScanStatus, ScanResult
from .scan_core import run_basic_scan, run_advanced_scan, available_scans
from .store import store, get_status, get_results

router = APIRouter(prefix="/scan", tags=["scan"])

@router.post("/basic", response_model=ScanStatus)
async def basic_scan(request: BasicScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid4())
    store[scan_id] = {"status": "in_progress", "results": []}
    background_tasks.add_task(run_basic_scan, scan_id, request.target, request.options, store)
    return {"scan_id": scan_id, "status": "in_progress"}

@router.post("/advanced", response_model=ScanStatus)
async def advanced_scan(request: AdvancedScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid4())
    store[scan_id] = {"status": "in_progress", "results": []}
    background_tasks.add_task(run_advanced_scan, scan_id, request.target, store)
    return {"scan_id": scan_id, "status": "in_progress"}

@router.get("/{scan_id}/status", response_model=ScanStatus)
async def check_status(scan_id: str):
    return get_status(scan_id)

@router.get("/{scan_id}/results", response_model=ScanResult)
async def check_results(scan_id: str):
    return get_results(scan_id)

@router.get("/available")
async def list_available_scans():
    return {"available": available_scans()}
