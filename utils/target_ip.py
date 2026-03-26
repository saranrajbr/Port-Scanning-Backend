import socket
from urllib.parse import urlparse

def target_ip(target):
    
    if not target:
        return None
    
    target=target.strip()
    
    
    if target.startswith("http://") or target.startswith("https://"):
        target=urlparse(target).netloc
        
        
    if target=="localhost":
        return "127.0.0.1"
    
    try:
        socket.inet_aton(target)
        return target
    except:
        pass
    
    
    try:
        target=socket.gethostbyname(target)
        return target
    except Exception:
        return None
    
    
