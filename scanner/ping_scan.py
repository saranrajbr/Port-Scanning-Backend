import socket
import datetime
import time
from utils.target_ip import target_ip


def ping_scan(target):
    
    terminal=[]
    table=[]
    
    ip=target_ip(target)
    
    if not ip:
        terminal.append("Invalid target")
        return [],{"active_hosts": 0, "threats": 0}, terminal
    
    terminal.append(f"pinging {ip}")
    
    source=socket.socket()
    source.settimeout(1)
    
    start=time.time()
    
    try:
        source.connect((ip,80))
        online=True
    except:
        online=False
        
    end=time.time()
    
    source.close()
    
    latency=round((end-start)*1000,2)
    
    if online:
        table.append({
            "ip":ip,
            "status":"online",
            "port":[],
            "os":"-",
            "latency":f"{latency} ms",
            "type":"ping",
            "time":str(datetime.datetime.now().time())
        })
        
        terminal.append(f"Reply from {ip} Latency {latency} ms")
        
    else:
        terminal.append("Request timeout")
        
    stats = {
        "active_hosts": len(table),
        "threats": 0
    }
    
    terminal.append("Ping Scan Done")
    
    return table,stats,terminal

