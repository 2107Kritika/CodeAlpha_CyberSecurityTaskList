from scapy.all import sniff, IP, TCP, UDP, Raw # type: ignore

def packet_callback(packet):
    if IP in packet:
        print("\n[+] Packet Captured:")
        print(f"    Source IP       : {packet[IP].src}")
        print(f"    Destination IP  : {packet[IP].dst}")
        print(f"    Protocol        : {packet[IP].proto}")

        if TCP in packet:
            print(f"    TCP Ports       : {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Ports       : {packet[UDP].sport} -> {packet[UDP].dport}")
        
        if Raw in packet:
            print(f"    Payload         : {bytes(packet[Raw].load)}")

# Capture 10 packets (set count=0 for infinite)
sniff(prn=packet_callback, count=10)
