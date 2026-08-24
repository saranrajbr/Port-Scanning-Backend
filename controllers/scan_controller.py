from scanner.arp_scan import arp_scan
from scanner.icmp_scan import icmp_scan
from scanner.ping_scan import ping_scan
from scanner.tcp_scan import tcp_scan
from scanner.udp_scan import udp_scan


def scan(target, mode, options=None):
    options = options or {}
    mode = mode.lower()

    if mode == "arp":
        return arp_scan(target, timeout=options.get("timeout", 2.0))

    if mode == "icmp":
        return icmp_scan(target, timeout=options.get("timeout", 1.0),
                         concurrency=options.get("concurrency", 64))

    if mode == "ping":
        return ping_scan(target, timeout=options.get("timeout", 1.0))

    if mode == "tcp":
        return tcp_scan(target,
                        ports=options.get("ports"),
                        timeout=options.get("timeout", 0.8),
                        concurrency=options.get("concurrency", 100),
                        service_detection=options.get("service_detection", True))

    if mode == "udp":
        return udp_scan(target,
                        ports=options.get("ports"),
                        timeout=options.get("timeout", 1.0),
                        concurrency=options.get("concurrency", 100))

    return None
