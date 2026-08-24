import shutil
import subprocess
import re


def ping_once(ip, timeout_sec=1):
    """True ICMP echo via the system ping binary (works unprivileged)."""
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return None
    try:
        proc = subprocess.run(
            [ping_bin, "-c", "1", "-W", str(int(timeout_sec)), ip],
            capture_output=True, text=True, timeout=timeout_sec + 2,
        )
        return proc.returncode == 0
    except Exception:
        return None


def parse_latency(output):
    match = re.search(r"time[=<]([\d.]+)\s*ms", output)
    if match:
        return f"{match.group(1)} ms"
    return "-"


def tcp_ping(ip, port=80, timeout=1.0):
    """Fallback reachability check via TCP connect when ICMP is unavailable."""
    import socket
    import time

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.time()
    try:
        sock.connect((ip, port))
        return round((time.time() - start) * 1000, 2)
    except Exception:
        return None
    finally:
        sock.close()


def ping_scan(target, timeout=1.0):
    from utils.target_ip import target_ip
    import datetime

    terminal = []
    ip = target_ip(target)

    if not ip:
        terminal.append("Invalid target: could not resolve host")
        return {"target": target, "ip": None, "ports": [], "table": [],
                "stats": {"active_hosts": 0, "threats": 0}, "terminal": terminal}

    terminal.append(f"Pinging {ip} with ICMP echo...")
    alive = ping_once(ip, timeout)

    latency = "-"
    if alive is None:
        terminal.append("ICMP unavailable, falling back to TCP connect probe")
        ms = tcp_ping(ip, 80, timeout)
        online = ms is not None
        if online:
            latency = f"{ms} ms"
    elif alive:
        try:
            out = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), ip],
                capture_output=True, text=True, timeout=timeout + 2,
            ).stdout
            latency = parse_latency(out)
        except Exception:
            pass
        online = True
    else:
        online = False

    table = []
    if online:
        table.append({
            "ip": ip,
            "status": "online",
            "ports": [],
            "os": "-",
            "latency": latency,
            "type": "ping",
            "time": str(datetime.datetime.now().time()),
        })
        terminal.append(f"Reply from {ip}: icmp_seq=1 time={latency}")
    else:
        terminal.append(f"Request timed out for {ip}")

    terminal.append("Ping scan done")

    return {"target": target, "ip": ip, "ports": [], "table": table,
            "summary": {"open": 0, "closed": 0, "filtered": 0, "total": 0},
            "os": {"name": None, "confidence": None},
            "stats": {"active_hosts": len(table), "threats": 0},
            "terminal": terminal}
