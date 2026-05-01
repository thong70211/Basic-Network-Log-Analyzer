from scapy.all import rdpcap, TCP, IP
import logging 

#Cấu hình logging
logging.basicConfig(
    filename="log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def HDSD():
    """HIỂN THỊ HƯỚNG DẪN SỬ DỤNG KHI CHẠY TOOL"""
    HDSD = """
    ===============================================
            BASIC NETWORK LOG ANALYZER
    ===============================================
        [Hướng dẫn nhanh]
        Bước 1: Đưa file pcap cần phân tích vào cùng thư mục với tool này
        Bước 2: Đổi giá trị của biến packets ở dòng thứ x thành ("tên_file_của_bạn.pcap") [hoặc đổi tên file pcap của bạn thành file.pcap]
        Bước 3: Tải công cụ cần thiết bằng lệnh: "pip install scapy" hoặc: "pip3 install scapy" (copy bỏ dấu ngoặc kép trong Terminal hoặc PowerShell)
        Bước 4: Chạy tool bằng lệnh: "python basic-network-tool.py" hoặc "python3 basic-network-tool.py" (copy bỏ dấu ngoặc kép trong Terminal hoặc PowerShell)
        Kết quả phân tích sẽ được hiển thị ngay bên dưới, và được lưu vào file: "log.txt"
    """
    print(HDSD)

HDSD()
try:
    packets = rdpcap("file.pcap")
except FileNotFoundError:
    print("Can not find pcap file!")
    exit()

ip_count = {}

"""
Danh sách các cổng dịch vụ tiêu chuẩn (Whitelisted Ports):
80 (HTTP), 443 (HTTPS/QUIC), 53 (DNS), 22 (SSH), 
25/465/587 (SMTP), 993 (IMAP)

"""
allowed_port = {80, 443, 53, 22, 25, 465, 587, 993}

for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport

        ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
        
        if dst_port not in allowed_port:
            msg = f"Suspicious port {dst_port} requested by IP {src_ip} "

            print(msg) #Hiển thị port lạ ra màn hình
            logging.warning(msg) #Ghi vào file log

for ip,count in ip_count.items():
    if (count > 50):
        msg = f"Possible spam detected by {ip}, total request: {count}"

        print(msg) #Hiển thị IP có thể là spam ra màn hình
        logging.warning(msg) #Ghi vào file log
