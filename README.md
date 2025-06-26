# 🕵️‍♂️ Network Packet Sniffer

A real-time network packet sniffer built with **Python** and **Scapy**. This tool captures and analyzes network packets, extracts important header information, and displays protocol-level details—perfect for learning, debugging, and diagnostics.

---

## 📦 Features

- Live packet capturing from network interfaces
- Parses and displays:
  - Ethernet, IP, TCP, UDP, ICMP headers
  - Source & destination IPs and ports
  - Protocol types and flags
- Easy-to-understand console output
- Lightweight and extensible

---

## 🔧 Requirements

- Python 3.6+
- [Scapy](https://scapy.readthedocs.io/en/latest/)

Install with:

```bash
pip install scapy

🚀 Usage
1. Run the sniffer:
  sudo python3 sniffer.py
You may need to run it with sudo to access raw sockets.
2. Output Example
  [+] Packet Captured:
        Ethernet Frame:
            Source MAC: aa:bb:cc:dd:ee:ff
            Destination MAC: ff:ee:dd:cc:bb:aa
        IP Packet:
            Source IP: 192.168.1.10
            Destination IP: 172.217.27.46
            Protocol: TCP
        TCP Segment:
            Source Port: 50321
            Destination Port: 443
            Flags: SYN
📁 File Structure

  network-packet-sniffer/
├── sniffer.py        # Main script to start sniffing and display parsed packets
├── README.md         # Project documentation

🔍 Sample Code (sniffer.py)
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("\n[+] Packet Captured:")
    if Ether in packet:
        eth = packet[Ether]
        print(f"    Ethernet Frame:\n        Source MAC: {eth.src}\n        Destination MAC: {eth.dst}")

    if IP in packet:
        ip = packet[IP]
        print(f"    IP Packet:\n        Source IP: {ip.src}\n        Destination IP: {ip.dst}\n        Protocol: {ip.proto}")

        if TCP in packet:
            tcp = packet[TCP]
            print(f"    TCP Segment:\n        Source Port: {tcp.sport}\n        Destination Port: {tcp.dport}\n        Flags: {tcp.flags}")
        elif UDP in packet:
            udp = packet[UDP]
            print(f"    UDP Segment:\n        Source Port: {udp.sport}\n        Destination Port: {udp.dport}")
        elif ICMP in packet:
            icmp = packet[ICMP]
            print(f"    ICMP Packet:\n        Type: {icmp.type}\n        Code: {icmp.code}")

sniff(prn=packet_callback, store=False)

🧠 Use Cases
Network diagnostics & troubleshooting

Educational purposes in cybersecurity/networking

Real-time traffic monitoring

Packet inspection for suspicious activity

⚠️ Disclaimer
This tool is intended only for educational and authorized testing purposes. Do not use it on networks you do not own or have permission to monitor.

📜 License
MIT License. See LICENSE file for more details.


🤝 Contributing
Feel free to fork and improve the project. Pull requests are welcome!
---

Let me know if you'd like a logo, badge integration (like Travis CI, PyPI), or advanced features like saving to `.pcap`, filtering by port/protocol, or GUI support.
