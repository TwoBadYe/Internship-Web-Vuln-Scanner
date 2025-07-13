# app/store.py
store = {}

def get_status(scan_id):
    if scan_id not in store:
        return {"scan_id": scan_id, "status": "not_found"}
    return {"scan_id": scan_id, "status": store[scan_id]["status"]}

def get_results(scan_id):
    if scan_id not in store:
        return {"scan_id": scan_id, "target": "", "findings": []}
    return {"scan_id": scan_id, "target": store[scan_id].get("target", ""), "findings": store[scan_id]["results"]}