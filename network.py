import socket
import struct
import time
from scapy.all import *
import dns.resolver
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.layers.inet import ICMP
from scapy.layers.l2 import ARP

from scapy.layers.inet import IP, ICMP


def google_icmp():
    HOST = 'www.google.com'
    packet = IP(dst=HOST) / ICMP()
    start_time = time.time()
    reply = sr1(packet, timeout=2, verbose=False)
    end_time = time.time()
    rtt = (end_time - start_time) * 1000
    if reply:
        print(f"Response received from {HOST}: rtt = {round(rtt, 2)} ms")
    else:
        print(f"No response received from {HOST}")


def tcp():
    HOST = 'www.google.com'
    PORT = 80
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (HOST, PORT)
    sock.connect(server_address)
    request = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
    sock.sendall(request)
    response = sock.recv(1024)
    print(response)
    sock.close()

# DNS code
def dns():
    import dns.resolver
    domain = 'baramen.com'
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['8.8.8.8']
    answers = my_resolver.query(domain)
    for rdata in answers:
        print(rdata.address)
    icmp_packet = IP(dst='google.com') / ICMP()
    send(icmp_packet)
    HOST = 'www.google.com'
    PORT = 80
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((HOST, PORT))
    if result == 0:
        print("Website is accessible!")
    else:
        print("Website is not accessible.")
    sock.close()


# ARP code
def arp():
    target_mac = "00:0c:29:68:6f:56"
    target_ip = "192.168.1.1"
    arp_packet = Ether(dst=target_mac) / ARP(op="who-has", pdst=target_ip)
    sendp(arp_packet)
    icmp_packet = IP(dst='google.com') / ICMP()
    send(icmp_packet)
    HOST = 'www.google.com'
    PORT = 80
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((HOST, PORT))
    if result == 0:
        print("Website is accessible!")
    else:
        print("Website is not accessible.")
    sock.close()


# UDP code
def udp():
    HOST = 'localhost'
    PORT = 8000
    packet = b'Hello, World!'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (HOST, PORT))
    icmp_packet = b''
    sock.sendto(icmp_packet, ('google.com', 0))
    HOST = 'www.google.com'
    PORT = 80
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((HOST, PORT))
    if result == 0:
        print("Website is accessible!")
    else:
        print("Website is not accessible.")
    sock.close()

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
# ip_header = b'\x45\x00\x00\x1c' # Version, IHL, Type of Service | Total Length
# ip_header += b'\xab\xcd\x00\x00' # Identification | Flags, Fragment Offset
# ip_header += b'\x40\x01\x6b\xd8' # TTL, Protocol | Header Checksum
# ip_header += b'\xc0\xa8\x92\x83' # Source Address
# ip_header += b'\x08\x08\x08\x08' # Destination Address
# icmp_header = b'\x08\x00\xe5\xca' # Type of message, Code | Checksum
# icmp_header += b'\x12\x34\x00\x01' # Identifier | Sequence Number
# packet = ip_header + icmp_header
# s.sendto(packet, ('8.8.8.8', 0))

def icmp():
    icmp_pck = socket.getprotobyname("icmp")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW , icmp_pck)
    client_socket.settimeout(1)
    ip_address = socket.gethostbyname('www.google.com')
    # ip_address=8.8.8.8

    # print("client_socket.settimeout(1.0)" + client_socket.settimeout(1.0))
    type = 8  # Echo Request
    code = 0
    checksum = 0
    identifier = 0
    seq_number = 1
    data = b'Hello, World!'
    icmp_packet = struct.pack('!BBHHH', type, code, checksum, identifier, seq_number) + data
    # print("icmp_packet"+icmp_packet)

    for i in range(0, len(icmp_packet), 2):
        # if i + 1 < len(icmp_packet):
        if i+1<len(icmp_packet)-1:
            w = (icmp_packet[i] << 8) + icmp_packet[i + 1]
            checksum += w
            # print("checksum")
            # print( checksum)
        else:
            # print("error")
            w=(icmp_packet[i]<<8)
            checksum+=w
    checksum = (checksum >> 16) + (checksum & 0xffff)

    checksum = ~checksum & 0xffff
    icmp_packet = struct.pack('!BBHHH', type, code, checksum, identifier, seq_number) + data
    client_socket.sendto(icmp_packet, ('google.com', 0))
    try:
        client_socket.sendto(icmp_packet, ('google.com', 0))
        start_time = time.time()
        ready = select.select([client_socket], [], [], 1)
        end_time = time.time()
        if ready[0]:
            packet, address = client_socket.recvfrom(1024)
            elapsed_time = (end_time - start_time) * 1000
            print(f"Ping to google.com succeeded. Response time: {elapsed_time:.2f} ms")
        else:
            print(f"Request timed out for google.com")
    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        client_socket.close()


# Build an Ethernet frame
def build_ethernet_frame(dest_mac, src_mac, ether_type, payload):
    eth_header = struct.pack("!6s6sH", dest_mac, src_mac, ether_type)
    ethernet_frame = eth_header + payload
    return ethernet_frame


def ethernet():
    eth_frame = Ether(dst='12:34:56:78:9a:bc', src='de:ad:be:ef:01:23')
    ip_packet = IP(src='192.168.1.10', dst='8.8.8.8') / UDP() / Raw(b'This is a test message')
    packet = eth_frame / ip_packet
    send(packet, iface='Ethernet')


if __name__ == '__main__':
    inp = input("choose:")
    if (inp == 'tcp'):
        tcp()
    if (inp == 'udp'):
        udp()
    if (inp == 'icmp'):
        icmp()
    if (inp == 'ethernet'):
        ethernet()
    if (inp == 'dns'):
        dns()
    if (inp == 'arp'):
        arp()
    google_icmp()