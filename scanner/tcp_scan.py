import socket
import datetime
from utils.os_detection import detect_os
from utils.target_ip import target_ip

common_ports=[21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080]

def tcp_scan(target):
    
    open_port=[]
    terminal=[]
    
    ip=target_ip(target)
    
    if not ip:
        terminal.append("Invalid target")
        return [],{"active_hosts":0,"threads":0},terminal
    
    terminal.append(f"scanning {ip}")
    
    for port in common_ports:
        source=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        source.settimeout(0.8)
        
        try:
            source.connect((ip,port))
            open_port.append(port)
            terminal.append(f"OPEN {port}")
            
        except:
            pass
        
        source.close()
        
    os=detect_os(open_port)
    
    terminal.append(f"os detected: {os}")
    
    table=[{
        "ip":ip,
        "status":"online",
        "ports":open_port,
        "os":os,
        "latency":"-",
        "type":"host",
        "time":str(datetime.datetime.now().time())
    }]
    
    stats={
        "active_hosts":1 if open_port else 0,
        "threats":0
    }
    
    return table,stats,terminal
    
    
