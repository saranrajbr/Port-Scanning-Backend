import socket
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.target_ip import target_ip
from utils.port_data import service_name, risk_for


def probe_udp(ip, port, timeout):
    result = {"port": port, "protocol": "UDP", "state": "FILTERED",
              "service": service_name(port), "banner": None, "risk": "-"}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"probe")
        data, _ = sock.recvfrom(1024)
        result["state"] = "OPEN"
        result["risk"] = risk_for(port)
        if data:
            result["banner"] = data.decode("utf-8", errors="replace").strip()[:120]
    except socket.timeout:
        # No reply: port is open or filtered (UDP gives no ACK for closed drops)
        pass
    except ConnectionRefusedError:
        result["state"] = "CLOSED"
    except OSError:
        result["state"] = "CLOSED"
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return result


def udp_scan(target, ports=None, timeout=1.0, concurrency=100):
    terminal = []
    ip = target_ip(target)

    if not ip:
        terminal.append("Invalid target: could not resolve host")
        return {"target": target, "ip": None, "ports": [], "table": [],
                "stats": {"active_hosts": 0, "threats": 0}, "terminal": terminal}

    port_list = ports or []
    terminal.append(f"Resolved {target} -> {ip}")
    terminal.append(f"Starting UDP scan on {len(port_list)} ports "
                    f"(timeout={timeout}s, concurrency={concurrency})")

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 500))) as pool:
        futures = {pool.submit(probe_udp, ip, p, timeout): p for p in port_list}
        done_count = 0
        for future in as_completed(futures):
            res = future.result()
            done_count += 1
            results.append(res)
            if res["state"] == "OPEN":
                terminal.append(f"OPEN  {res['port']}/udp  {res['service']}")
            if done_count % max(1, len(port_list) // 10) == 0:
                terminal.append(f"progress: {done_count}/{len(port_list)} ports probed")

    open_ports = sorted(r["port"] for r in results if r["state"] == "OPEN")
    summary = {
        "open": len(open_ports),
        "closed": sum(1 for r in results if r["state"] == "CLOSED"),
        "filtered": sum(1 for r in results if r["state"] == "FILTERED"),
        "total": len(port_list),
    }

    terminal.append(f"UDP scan complete: {summary['open']} open, "
                    f"{summary['closed']} closed, {summary['filtered']} open|filtered")

    table = [{
        "ip": ip,
        "status": "online" if open_ports else "no-open-ports",
        "ports": open_ports,
        "os": "-",
        "latency": "-",
        "type": "host",
        "time": str(datetime.datetime.now().time()),
    }]

    stats = {"active_hosts": 1, "threats": summary["open"]}

    return {"target": target, "ip": ip, "ports": sorted(results, key=lambda r: r["port"]),
            "summary": summary, "os": {"name": None, "confidence": None},
            "table": table, "stats": stats, "terminal": terminal}
