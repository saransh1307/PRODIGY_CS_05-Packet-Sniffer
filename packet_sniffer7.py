import socket
import struct

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(1024)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('Ethernet Information...')
        print('Destination_mac: {}'.format(dest_mac))
        print('Source_mac: {}'.format( src_mac))
        print('Ethernet Protocol Type:', eth_proto)


        if eth_proto == 8:
            version, header_length, src_IP, dest_IP, ttl, proto, data = IPv4_Packet(data)
            print('Packet Information')
            print('\t\tversion: {}, Header_length: {}'.format(version, header_length))
            print('\t\tTTL: {}, Protocol: {}'.format(ttl, proto))
            print('\t\tSource_IP: {}, Destination_IP: {}'.format(src_IP, dest_IP))
            data = bytes_to_ASCII(data)
            print('\t\tData: {} '.format(data))


            if proto == 1:
                icmp_type, code, checksum, data = ICMP_proto(data)
                print('ICMP PACKET: ')
                print('\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                data = bytes_to_ASCII(data)
                print('\t\tDATA: {}'.format(data))

            elif proto == 6:
                src_port, dest_port, seq, ack, offset_reserver_flags, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = TCP_proto(data)
                print('TCP PROTOCOL')
                print('\t\tSource port: {}, Destination port: {}, Sequence: {}, Acknowledgment: {}'.format(src_port, dest_port, seq, ack))
                print('\t\tFlag_urg: {}, Flag_ack: {}, Flag_psh: {}, Flag_rst: {}, Flag_syn: {}, Flag_fin: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                data = bytes_to_ASCII(data)
                print('\t\tData:{}'.format(data))
                
                if dest_port == 80 | src_port == 80:
                    http_text = http_data(data)
                    print('HTTP data: {}'.format(http_text))

            elif proto == 17:
                src_port, dest_port, size, checksum = UDP_Packet(data)
                print('UDP PROTOCOL...')
                print('\t\t Source_port: {}'.format(src_port))
                print('\t\t Destination_port: {}'.format(dest_port))
                print('\t\t Size: {}'.format(size))
                print('\t\t Checksum: {}'.format(checksum))
        else:
            print('Unknown packet protocol...{RESTARTING}')
            main()

def ethernet_frame(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return formatted_mac(dest_mac), formatted_mac(src_mac), socket.ntohs(eth_proto), data[14:]

def formatted_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

def IPv4_Packet(data):
    version_header = data[0]
    version = version_header >> 4
    header_length = (version_header & 15) * 4
    ttl, proto, src_IP, dest_IP = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, formatted_IP(src_IP), formatted_IP(dest_IP), ttl, proto, data[header_length:]

def formatted_IP(IP_addr):
    IP = '.'.join(map(str, IP_addr))
    return IP

def ICMP_proto(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def TCP_proto(data):
    src_port, dest_port, seq, ack, offset_reserver_flags = struct.unpack('! H H L L H', data[:14])
    offset = offset_reserver_flags >> 12
    flag_urg = (offset_reserver_flags & 32) >> 5
    flag_ack = (offset_reserver_flags & 16) >> 4
    flag_psh = (offset_reserver_flags & 8) >> 3
    flag_rst = (offset_reserver_flags & 4) >> 2
    flag_syn = (offset_reserver_flags & 2) >> 1
    flag_fin = (offset_reserver_flags & 1) 
    return src_port, dest_port, seq, ack, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin


def UDP_Packet(data):
    src_port, dest_port, size, checksum = struct.unpack('!H H 2s H', data[:8])
    return src_port, dest_port, size, checksum

def bytes_to_ASCII(bytes_data):
    ascii_string = bytes_data.decode("ASCII", errors="ignore")
    return ascii_string

def http_data(data):
    try:
        http_text = data.decode('utf-8')
        print(http_text)
    except UnicodeDecodeError:
        print('failed to decode http data')
main()