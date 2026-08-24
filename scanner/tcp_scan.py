import socket
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.os_detection import detect_os
from utils.target_ip import target_ip
from utils.port_data import service_name, risk_for

HTTPISH_PORTS = {80, 443, 8080, 8000, 8008, 8443, 8888}


def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        sock.connect((ip, port))
        if port in HTTPISH_PORTS:
            sock.send(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        else:
            sock.send(b"\r\n")
        data = sock.recv(1024)
        sock.close()
        banner = data.decode("utf-8", errors="replace").strip().splitlines()
        return banner[0][:120] if banner else None
    except Exception:
        return None


def probe_tcp(ip, port, timeout, service_detection):
    result = {"port": port, "protocol": "TCP", "state": "CLOSED",
              "service": service_name(port), "banner": None, "risk": "-"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        result["state"] = "OPEN"
        result["risk"] = risk_for(port)
        if service_detection:
            result["banner"] = grab_banner(ip, port)
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result


def tcp_scan(target, ports=None, timeout=0.8, concurrency=100, service_detection=True):
    terminal = []
    ip = target_ip(target)

    if not ip:
        terminal.append("Invalid target: could not resolve host")
        return {"target": target, "ip": None, "ports": [], "table": [],
                "stats": {"active_hosts": 0, "threats": 0}, "terminal": terminal}

    port_list = ports or []
    terminal.append(f"Resolved {target} -> {ip}")
    terminal.append(f"Starting TCP scan on {len(port_list)} ports "
                    f"(timeout={timeout}s, concurrency={concurrency})")

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 500))) as pool:
        futures = {pool.submit(probe_tcp, ip, p, timeout, service_detection): p for p in port_list}
        done_count = 0
        for future in as_completed(futures):
            res = future.result()
            done_count += 1
            results.append(res)
            if res["state"] == "OPEN":
                line = f"OPEN  {res['port']}/tcp  {res['service']}"
                if res.get("banner"):
                    line += f"  [{res['banner']}]"
                terminal.append(line)
            if done_count % max(1, len(port_list) // 10) == 0:
                terminal.append(f"progress: {done_count}/{len(port_list)} ports probed")

    open_ports = [r["port"] for r in results if r["state"] == "OPEN"]
    open_ports.sort()

    os_info = detect_os(open_ports)
    summary = {
        "open": len(open_ports),
        "closed": sum(1 for r in results if r["state"] == "CLOSED"),
        "filtered": 0,
        "total": len(port_list),
    }

    terminal.append(f"OS fingerprint: {os_info['name'] or 'unknown'}")
    terminal.append(f"TCP scan complete: {summary['open']} open / {summary['total']} scanned")

    table = [{
        "ip": ip,
        "status": "online" if open_ports else "no-open-ports",
        "ports": open_ports,
        "os": os_info["name"] or "-",
        "latency": "-",
        "type": "host",
        "time": str(datetime.datetime.now().time()),
    }]

    stats = {"active_hosts": 1, "threats": summary["open"]}

    return {"target": target, "ip": ip, "ports": sorted(results, key=lambda r: r["port"]),
            "summary": summary, "os": os_info, "table": table, "stats": stats,
            "terminal": terminal}
