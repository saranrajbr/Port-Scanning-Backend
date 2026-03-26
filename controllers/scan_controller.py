from scanner.arp_scan import arp_scan
from scanner.icmp_scan import icmp_scan
from scanner.ping_scan import ping_scan
from scanner.tcp_scan import tcp_scan
from scanner.udp_scan import udp_scan


def scan(target,mode):
    
    mode=mode.lower()
    
    if mode=="arp":
        return arp_scan(target)
    
    if mode=="icmp":
        return icmp_scan(target)
    
    if mode=="ping":
        return ping_scan(target)
    
    if mode=="tcp":
        return tcp_scan(target)
    
    if mode=="udp":
        return udp_scan(target)
    
    return [],{},[]

