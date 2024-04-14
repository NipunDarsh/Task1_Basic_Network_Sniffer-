import socket
import struct
import textwrap
import time

def main():
    # Create a raw socket
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        # Receive a packet
        raw_data, addr = conn.recvfrom(65535)

        # Parse Ethernet frame
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # Parse IP packets
        if eth_proto == 8:
            version, header_length, ttl, proto, src_ip, dest_ip, data = ipv4_packet(data)

            # Packet Sizes
            packet_size = len(raw_data)

            # Timestamp
            timestamp = time.strftime('%H:%M:%S', time.localtime())

            # Protocol Information
            if proto == 1:
                protocol = "ICMP"
            elif proto == 6:
                protocol = "TCP"
            elif proto == 17:
                protocol = "UDP"
            else:
                protocol = "Other"

            # Packet Contents
            packet_contents = data[:30].decode('utf-8', errors='ignore')

            # Network Troubleshooting
            troubleshooting = "Congestion detected"  # Placeholder for troubleshooting information

            # Print packet details
            print("Source IP: {}, Destination IP: {}".format(src_ip, dest_ip))
            print("Source MAC: {}, Destination MAC: {}".format(src_mac, dest_mac))
            print("Protocol: {}".format(protocol))
            print("Packet Contents: {}".format(packet_contents))
            print("Packet Size: {}B".format(packet_size))
            print("Timestamp: {}".format(timestamp))
            print("Network Troubleshooting: {}".format(troubleshooting))
            print()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(dest), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

if __name__ == "__main__":
    main()

