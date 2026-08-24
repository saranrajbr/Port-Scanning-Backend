import datetime

from flask import Blueprint, g, jsonify, request

from controllers.scan_controller import scan
from middleware.auth_middleware import token_required
from models.scan_model import delete_scan, get_scan, get_scans, save_scan
from utils.port_data import resolve_port_list

scan_router = Blueprint("scan_router", __name__)

VALID_MODES = {"tcp", "udp", "arp", "ping", "icmp"}


def _float(value, default, lo, hi):
    try:
        return min(max(float(value), lo), hi)
    except (TypeError, ValueError):
        return default


def _int(value, default, lo, hi):
    try:
        return min(max(int(value), lo), hi)
    except (TypeError, ValueError):
        return default


@scan_router.route("/scan", methods=["POST"])
@token_required
def run_scan():
    data = request.get_json(silent=True) or {}

    target = str(data.get("target") or "").strip()
    mode = str(data.get("mode") or "").lower()

    if not target or not mode:
        return jsonify({"error": "target and mode are required"}), 400

    if mode not in VALID_MODES:
        return jsonify({"error": f"mode must be one of {sorted(VALID_MODES)}"}), 400

    options = {
        "timeout": _float(data.get("timeout"), 0.8 if mode == "tcp" else 1.0, 0.2, 10),
        "concurrency": _int(data.get("concurrency"), 100, 1, 500),
        "service_detection": bool(data.get("serviceDetection", True)),
    }

    ports_error = None
    if mode in ("tcp", "udp"):
        spec = data.get("range") or "top100"
        custom = data.get("customPorts")
        try:
            options["ports"] = resolve_port_list(spec, custom=custom, mode=mode)
        except ValueError as exc:
            ports_error = str(exc)

    if ports_error:
        return jsonify({"error": f"invalid port list: {ports_error}"}), 400

    started = datetime.datetime.now(datetime.timezone.utc)

    try:
        result = scan(target, mode, options)
    except Exception as exc:
        return jsonify({"error": f"scan failed: {exc}"}), 500

    if result is None:
        return jsonify({"error": f"unsupported scan mode '{mode}'"}), 400

    finished = datetime.datetime.now(datetime.timezone.utc)
    duration_sec = round((finished - started).total_seconds(), 1)

    risky_ports = sorted({
        p["port"] for p in result.get("ports", []) if p.get("risk") == "High"
    })

    document = {
        **result,
        "user": g.user,
        "mode": mode.upper(),
        "status": "Completed",
        "duration": duration_sec,
        "risky_ports": risky_ports,
        "created_at": finished.isoformat(),
    }

    saved = save_scan(document)
    return jsonify(saved), 200


@scan_router.route("/scans", methods=["GET"])
@token_required
def list_scans():
    try:
        scans = get_scans(g.user)
    except Exception as exc:
        return jsonify({"error": f"database unavailable: {exc}", "scans": []}), 503
    return jsonify({"scans": scans}), 200


@scan_router.route("/scans/<scan_id>", methods=["GET"])
@token_required
def read_scan(scan_id):
    try:
        doc = get_scan(g.user, scan_id)
    except Exception as exc:
        return jsonify({"error": f"database unavailable: {exc}"}), 503
    if not doc:
        return jsonify({"error": "scan not found"}), 404
    return jsonify(doc), 200


@scan_router.route("/scans/<scan_id>", methods=["DELETE"])
@token_required
def remove_scan(scan_id):
    try:
        removed = delete_scan(g.user, scan_id)
    except Exception as exc:
        return jsonify({"error": f"database unavailable: {exc}"}), 503
    if not removed:
        return jsonify({"error": "scan not found"}), 404
    return jsonify({"msg": "scan deleted"}), 200


@scan_router.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200
