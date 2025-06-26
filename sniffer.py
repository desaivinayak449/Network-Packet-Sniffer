from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print("\n[+] Packet Captured:", packet.summary())
        print(f"    Source IP: {ip_layer.src} --> Destination IP: {ip_layer.dst}")
        
        if TCP in packet:
            print(f"    Protocol: TCP | Src Port: {packet[TCP].sport} --> Dst Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    Protocol: UDP | Src Port: {packet[UDP].sport} --> Dst Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"    Protocol: ICMP")
        else:
            print("    Other Protocol")

# Start sniffing on default interface (or pass iface="eth0")
print("[*] Starting Packet Sniffer (Press Ctrl+C to stop)...")
sniff(prn=process_packet, store=False)
