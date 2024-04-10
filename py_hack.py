from scapy.all import sniff
from scapy.layers.http import HTTPRequest, HTTPResponse

def http_callback(packet):
    if HTTPRequest in packet:
        http_layer = packet[HTTPRequest]
        print(f"Request:\n\tHost: {http_layer.Host.decode()}\n\tMethod: {http_layer.Method.decode()}\n\tPath: {http_layer.Path.decode()}\n\n")

    if HTTPResponse in packet:
        http_layer = packet[HTTPResponse]
        status_code = int(http_layer.Status_Code.decode())
        print("Response:")
        print(f"\tCode: {status_code}")
        if status_code in [301, 302]:
            print(f"\tRedirect Location: {http_layer.Location.decode()}")
            print('\n')

packets = sniff(filter="port 80", prn=http_callback, store=0)