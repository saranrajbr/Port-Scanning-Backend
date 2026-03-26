import socket
import datetime
from utils.os_detection import detect_os
from utils.target_ip import target_ip

def icmp_scan(target):
    terminal=[]
    table=[]
    
    ip=target_ip(target)
    
    if not ip:
        terminal.append("Invalid target")
        return [],{"active_hosts":0,"threads":0},terminal
    
    terminal.append(f"Scanning {ip}")
    
    source=socket.socket()
    source.settimeout(1)
    
    
    try:
        source.connect((ip,443))
        online=True
    except:
        online=False
        
    source.close()
    
    os=detect_os([443])
    
    if online:
        table.append({
            "ip":ip,
            "status":"online",
            "ports":[443],
            "os":os,
            "latency":"-",
            "type":"host",
            "time":str(datetime.datetime.now().time())
        })
        terminal.append("Host reachable")
        terminal.append(f"OS detected: {os}")
    else:
        terminal.append("Host not reachable")
    
    status={
        "active hosts":1,
        "threads":0
    }
        
    terminal.append("ICMP Scan Done.....")
        
    return table,status,terminal

    


    
    