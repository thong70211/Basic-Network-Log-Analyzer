from scapy.all import rdpcap, TCP, IP
import logging 
import argparse

"""
====================================
    CONFIGURATION
====================================
"""

#Configure logging
logging.basicConfig(
    filename="log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

"""
Popular ports list (Whitelisted Ports):
80 (HTTP), 443 (HTTPS/QUIC), 53 (DNS), 22 (SSH), 
25/465/587 (SMTP), 993 (IMAP)
"""
ALLOWED_PORTS = {
    80, #HTTP
    443, #HTTPS/QUIC
    53, #DNS
    22, #SSH
    25, #SMTP
    465, #SMTPS
    587, #SMTP (submission)
    993 #IMAP
    }

# NOTE: Adjust this threshold based on system behavior.
# High-traffic services (e.g., e-commerce) may require higher values.
SPAM_THRESHOLD = 50

"""
====================================
    CORE LOGIC
====================================
"""
def analyze_pcap(file_name):
    try:
        packets = rdpcap(file_name)
    except FileNotFoundError:
        print("Can not find pcap file!")
        return

    ip_count = {}

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_port = pkt[TCP].dport

            ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
            
            if dst_port not in ALLOWED_PORTS:
                msg = f"Suspicious port {dst_port} requested from IP {src_ip} "

                print(msg) 
                logging.warning(msg) 

    for ip,count in ip_count.items():
        if (count > SPAM_THRESHOLD):
            msg = f"Possible spam detected from {ip}, total request: {count}"

            print(msg)
            logging.warning(msg) 

"""
====================================
    MAIN
====================================
"""
def main():
    parser = argparse.ArgumentParser(description="Basic PCAP Analyzer")
    parser.add_argument("pcap_file", help="Path to the pcap file")

    args = parser.parse_args()

    analyze_pcap(args.pcap_file)

if __name__ == "__main__":
    main()