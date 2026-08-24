import ipaddress
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.target_ip import target_ip


def derive_subnet(ip):
    try:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return [str(h) for h in network.hosts()]
    except ValueError:
        return []


def check_host(ip, timeout=1):
    from scanner.ping_scan import ping_once
    return ip if ping_once(ip, timeout) else None


def icmp_scan(target, timeout=1.0, concurrency=64):
    """Ping-sweep the target's /24 subnet to discover live hosts."""
    import datetime

    terminal = []
    resolved = target_ip(target)

    if not resolved:
        terminal.append("Invalid target: could not resolve host")
        return {"target": target, "ip": None, "ports": [], "table": [],
                "stats": {"active_hosts": 0, "threats": 0}, "terminal": terminal}

    hosts = derive_subnet(resolved)
    terminal.append(f"ICMP sweep of subnet {hosts[0].rsplit('.', 1)[0]}.0/24 ({len(hosts)} hosts)")
    terminal.append(f"Probing with {concurrency} parallel workers...")

    live_hosts = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(check_host, h, timeout): h for h in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                live_hosts.append(result)
                terminal.append(f"HOST UP  {result}")

    live_hosts.sort(key=lambda h: tuple(map(int, h.split("."))))

    now = str(datetime.datetime.now().time())
    table = [{
        "ip": h,
        "status": "online",
        "ports": [],
        "os": "-",
        "latency": "-",
        "type": "host",
        "time": now,
    } for h in live_hosts]

    terminal.append(f"ICMP sweep complete: {len(live_hosts)} live hosts found")

    return {"target": f"{resolved}/24", "ip": resolved, "ports": [], "table": table,
            "summary": {"open": 0, "closed": 0, "filtered": 0, "total": len(hosts)},
            "os": {"name": None, "confidence": None},
            "stats": {"active_hosts": len(live_hosts), "threats": 0},
            "terminal": terminal}
