def detect_os(port):
    if 3389 in port:
        return "Windows"
    
    if 22 in port:
        return "Linux"
    
    if 445 in port:
        return "Windows"
    
    if 80 in port and 443 in port:
        return "Linux"
    
    return "unknown"