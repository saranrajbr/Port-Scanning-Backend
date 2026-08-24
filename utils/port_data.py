TOP_100_TCP = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    5000, 5631, 631, 2077, 2121, 6002, 873, 1755, 5901, 5061,
    9001, 49153, 3, 311, 5009, 7070, 5432, 1900, 13, 1028,
    9, 5051, 6646, 49156, 2021, 617, 81, 3690, 5100, 119,
    2068, 12, 212, 1911, 3659, 5405, 7777, 427, 1058, 1059,
    1080, 4001, 2049, 123, 1521, 543, 79, 998, 7100, 512,
]

TOP_UDP = [
    53, 123, 67, 68, 69, 88, 111, 123, 137, 138,
    139, 161, 162, 177, 427, 500, 514, 520, 623, 626,
    1194, 1434, 1512, 161, 1645, 1646, 1701, 1812, 1813, 2049,
    4500, 5353, 5060, 11211, 1900, 6970, 3283, 49152, 49153, 5355,
]

SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP",
    79: "Finger", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    111: "RPCBind", 113: "Ident", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS Name", 138: "NetBIOS Datagram",
    139: "NetBIOS Session", 143: "IMAP", 144: "News", 161: "SNMP",
    162: "SNMP Trap", 177: "XDMCP", 179: "BGP", 389: "LDAP",
    427: "SLP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IKE/IPSec", 514: "Syslog", 515: "Printer", 520: "RIP",
    543: "klogin", 544: "kshell", 548: "AFP", 554: "RTSP",
    587: "Submission", 623: "IPMI", 631: "IPP/CUPS", 646: "LDP",
    873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1099: "Java RMI", 1194: "OpenVPN", 1433: "MSSQL", 1434: "MSSQL UDP",
    1512: "WINS", 1521: "Oracle DB", 1701: "L2TP", 1720: "H.323",
    1723: "PPTP", 1812: "RADIUS Auth", 2049: "NFS", 2082: "cPanel",
    2181: "ZooKeeper", 2222: "SSH Alt", 2375: "Docker HTTP",
    2376: "Docker TLS", 3000: "Node/Dev", 3128: "Squid Proxy",
    3260: "iSCSI", 3283: "Apple Remote", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4444: "Metasploit Default",
    4500: "IPSec NAT-T", 5000: "UPnP/Flask", 5060: "SIP",
    5061: "SIP TLS", 5353: "mDNS", 5432: "PostgreSQL",
    5555: "Android ADB", 5601: "Kibana", 5631: "pcAnywhere",
    5666: "NRPE", 5900: "VNC", 5901: "VNC-1", 5984: "CouchDB",
    6001: "X11", 6379: "Redis", 6646: "?", 7001: "WebLogic",
    7070: "RealServer", 7100: "X Font", 8000: "HTTP Alt",
    8008: "HTTP Alt", 8009: "AJP", 8080: "HTTP Proxy",
    8081: "HTTP Alt", 8443: "HTTPS Alt", 8888: "HTTP Alt",
    9001: "Tor Port", 9050: "Tor SOCKS", 9200: "Elasticsearch",
    9929: "Nmap Echo", 11211: "Memcached", 27017: "MongoDB",
    32768: "RPC", 49152: "Ephemeral", 49153: "Ephemeral",
    49154: "Ephemeral", 49156: "Ephemeral",
}

HIGH_RISK_PORTS = {23, 135, 137, 139, 445, 3389, 4444, 5555, 5900, 6379, 11211}
MEDIUM_RISK_PORTS = {21, 22, 1433, 1434, 1521, 1723, 3306, 5432, 5601, 9200, 27017}


def service_name(port):
    return SERVICES.get(port, "-")


def risk_for(port):
    if port in HIGH_RISK_PORTS:
        return "High"
    if port in MEDIUM_RISK_PORTS:
        return "Medium"
    return "-" if port > 1024 else "Low"


def parse_custom_ports(spec):
    ports = []
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            start, _, end = part.partition("-")
            if not (start.isdigit() and end.isdigit()):
                raise ValueError(f"invalid range '{part}'")
            lo, hi = int(start), int(end)
            if not (0 < lo <= hi <= 65535):
                raise ValueError(f"range out of bounds '{part}'")
            ports.extend(range(lo, hi + 1))
        elif part.isdigit():
            p = int(part)
            if not (0 < p <= 65535):
                raise ValueError(f"port out of bounds '{part}'")
            ports.append(p)
        else:
            raise ValueError(f"invalid port '{part}'")
    unique = sorted(set(ports))
    if len(unique) > 2000:
        raise ValueError("too many ports requested (max 2000)")
    return unique


def resolve_port_list(spec, custom=None, mode="tcp"):
    """spec: 'top100' | 'top1000' | 'custom' | None -> list of ints"""
    if spec == "custom":
        return parse_custom_ports(custom or "")
    if spec == "top1000":
        return list(range(1, 1025))
    pool = TOP_100_TCP if mode == "tcp" else TOP_UDP
    return list(pool[: min(100, len(pool))])
