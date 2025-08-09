# C Network Packet Sniffer

A basic packet sniffer written in C using `libpcap`.  
Captures and logs IP packet source and destination addresses in real-time.

---

## Features
- Sniffs live network traffic on the default network interface  
- Parses Ethernet and IPv4 headers  
- Prints source and destination IP addresses of captured packets  
- Easy to extend for more detailed packet analysis

---

## Requirements
- Linux/macOS system  
- `libpcap` development library installed (`libpcap-dev` or similar)  
- GCC compiler

---

## Build & Run

```bash
gcc simple_sniffer.c -lpcap -o simple_sniffer
sudo ./simple_sniffer
