from bson import ObjectId

from config.db import scandata


def _serialize(doc):
    if not doc:
        return None
    doc["id"] = str(doc.pop("_id"))
    return doc


def save_scan(scan):
    payload = {k: v for k, v in scan.items() if k != "id"}
    try:
        result = scandata.insert_one(payload)
        scan["id"] = str(result.inserted_id)
    except Exception:
        scan["id"] = None
    return scan


def get_scans(user, limit=100):
    docs = scandata.find({"user": user}).sort("created_at", -1).limit(limit)
    out = []
    for doc in docs:
        doc.pop("ports", None)
        doc.pop("terminal", None)
        doc.pop("table", None)
        out.append(_serialize(doc))
    return out


def get_scan(user, scan_id):
    try:
        oid = ObjectId(scan_id)
    except Exception:
        return None
    return _serialize(scandata.find_one({"_id": oid, "user": user}))


def delete_scan(user, scan_id):
    try:
        oid = ObjectId(scan_id)
    except Exception:
        return False
    result = scandata.delete_one({"_id": oid, "user": user})
    return result.deleted_count > 0
