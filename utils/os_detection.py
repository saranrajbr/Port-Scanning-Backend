WINDOWS_HINTS = {3389, 445, 139, 135}
LINUX_HINTS = {22}


def detect_os(open_ports):
    ports = set(open_ports)

    windows_score = len(ports & WINDOWS_HINTS)
    linux_score = len(ports & LINUX_HINTS)

    if windows_score > linux_score:
        confidence = min(60 + windows_score * 12, 95)
        return {"name": "Windows", "confidence": confidence}

    if linux_score:
        confidence = min(55 + linux_score * 20, 90)
        return {"name": "Linux", "confidence": confidence}

    if 80 in ports and 443 in ports:
        return {"name": "Linux (web server)", "confidence": 60}

    if ports:
        return {"name": None, "confidence": None}

    return {"name": None, "confidence": None}
