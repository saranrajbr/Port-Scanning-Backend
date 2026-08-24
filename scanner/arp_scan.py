import shutil
import subprocess


def arp_via_scapy(ip, timeout=2):
    try:
        from scapy.all import Ether, ARP, srp  # noqa: PLC0415
    except ImportError:
        return None

    try:
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                          timeout=timeout, verbose=False)
        for _, received in answered:
            return {"ip": received.psrc, "mac": received.hwsrc}
    except Exception:
        pass
    return None


def arp_via_arping(ip, timeout=2):
    bin_path = shutil.which("arping")
    if not bin_path:
        return None
    try:
        proc = subprocess.run([bin_path, "-c", "1", "-w", str(timeout), ip],
                              capture_output=True, text=True, timeout=timeout + 3)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "[" in line and "]" in line:
                    mac = line.split("[")[1].split("]")[0]
                    if mac.count(":") == 5:
                        return {"ip": ip, "mac": mac.upper()}
    except Exception:
        pass
    return None


def arp_via_neigh(ip):
    bin_path = shutil.which("ip")
    if not bin_path:
        return None
    try:
        out = subprocess.run([bin_path, "neigh", "show", ip],
                             capture_output=True, text=True, timeout=3).stdout
        for token in out.split():
            if token.count(":") == 5 and "FAILED" not in out and "INCOMPLETE" not in out:
                return {"ip": ip, "mac": token.upper()}
    except Exception:
        pass
    return None


def arp_scan(target, timeout=2.0):
    import datetime

    from utils.target_ip import target_ip

    terminal = []
    ip = target_ip(target)

    if not ip:
        terminal.append("Invalid target: could not resolve host")
        return {"target": target, "ip": None, "ports": [], "table": [],
                "stats": {"active_hosts": 0, "threats": 0}, "terminal": terminal}

    terminal.append(f"ARP resolving {ip} on the local network...")

    result = (arp_via_scapy(ip, timeout)
              or arp_via_arping(ip, timeout)
              or arp_via_neigh(ip))

    table = []
    if result:
        terminal.append(f"ARP reply {result['ip']} is-at {result['mac']}")
        terminal.append("Host is on the local network (layer-2 reachable)")
        table.append({
            "ip": result["ip"],
            "status": "online",
            "ports": [],
            "os": "-",
            "latency": "-",
            "type": "arp",
            "mac": result["mac"],
            "time": str(datetime.datetime.now().time()),
        })
    else:
        terminal.append(f"No ARP response from {ip}")
        terminal.append("Host may be offline, outside the LAN, or layer-2 "
                        "operations are unavailable in this environment")

    terminal.append("ARP scan done")

    return {"target": target, "ip": ip, "ports": [], "table": table,
            "summary": {"open": 0, "closed": 0, "filtered": 0, "total": 1},
            "os": {"name": None, "confidence": None},
            "stats": {"active_hosts": len(table), "threats": 0},
            "terminal": terminal}
