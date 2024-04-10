from scapy.all import *

# Function to intercept and process HTTP requests and responses
def sniff_http(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        if packet.haslayer(Raw):
            load = packet[Raw].load.decode(errors='ignore')
            if "HTTP" in load:
                print(f"[+] Connection: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
                print("[+] HTTP Request/Response:")
                print(load)
                print("=" * 50)

                # Проверка на наличие потенциально опасных строк в HTTP-сообщениях
                if "script" in load or "eval(" in load or "document.cookie" in load:
                    print("[!] Possible XSS Attack Detected!")
                    # Здесь можно добавить дополнительные действия по обработке атаки,
                    # например, блокировку соединения или запись в журнал
                    print("=" * 50)

# Start packet sniffing for HTTP traffic
sniff(filter="tcp port 80", prn=sniff_http, store=0)
