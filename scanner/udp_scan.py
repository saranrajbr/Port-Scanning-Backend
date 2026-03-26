import socket
import datetime
from utils.os_detection import detect_os
from utils.target_ip import target_ip


def udp_scan(target):
    
    terminal=[]
    open_port=[]
    table=[]
    
    common_port=[53,123,67]
    
    ip=target_ip(target)
    
    if not ip:
        terminal.append("Invalid target")
        return [],{"active_hosts":0,"threads":0},terminal
    
    for port in common_port:
        source=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        source.settimeout(1)
        
        
        try:
            source.sendto(b"test",(target,port))
            data,_=source.recvfrom(1024)
            
            open_port.append(port)
            terminal.append(f"UDP OPEN {port}")
            
            
        except socket.timeout:

            terminal.append(f"UDP OPEN|FILTERED {port}")
            open_port.append(port)

        except:

            terminal.append(f"UDP CLOSED {port}")

        source.close()
        
        os=detect_os(open_port)
        
        table.append({
            "ip":ip,
            "status":"online",
            "ports":open_port,
            "os":os,
            "latency":"-",
            "type":"host",
            "time":str(datetime.datetime.now().time())
            
        })
        
        stats={
            "active_hosts": 1 if open_port else 0,
            "threats": 0
        }
        
        terminal.append("UDP scan done")

        return table, stats, terminal
    
    
    

            
    
    