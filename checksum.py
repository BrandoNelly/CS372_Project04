import struct
import os


def get_ip_bytes(addresses):
    return bytes(map(int, addresses.split('.')))


def compute_checksum(pseudo_header, tcp_data):

    data = pseudo_header + tcp_data
    total = 0

    if len(data) % 2 == 1:
        data += b'\x00'

    for i in range(0, len(data), 2):

        word = int.from_bytes(data[i:i + 2], 'big')
        total += word
        total = (total >> 16) + (total & 0xFFFF)

    return (~total) & 0xFFFF


def gen_ip_pseudo_header(client_ip, dest_ip, tcp_length):
    client_bytes = get_ip_bytes(client_ip)
    dest_bytes = get_ip_bytes(dest_ip)
    zero = b'\x00'
    protocol = b'\x06'

    return client_bytes + dest_bytes + zero + protocol + struct.pack('!H', tcp_length)


def read_ip_address(file_path):
    with open(file_path, 'r') as f:
        return f.readline().strip().split()
    

def read_tcp_data(file_path):
    with open(file_path, 'rb') as f:
        return f.read()


def process_checksums(addr_file, data_file):

    source_ip, dest_ip = read_ip_address(addr_file)
    tcp_data = read_tcp_data(data_file)

    tcp_length = len(tcp_data)

    original_checksum = int.from_bytes(tcp_data[16:18], 'big')

    tcp_zero_cksum = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

    pseudo_header = gen_ip_pseudo_header(source_ip, dest_ip, tcp_length)

    computed_checksum = compute_checksum(pseudo_header, tcp_zero_cksum)

    # debugging checksum lengths
    #print(f"FilE: {addr_file}, original checksum: {original_checksum}, computed checksum: {computed_checksum}")

    if computed_checksum == original_checksum:
        print("PASS")
    else:
        print("FAIL")


folder_path = 'tcp_data'

for i in range(10):
    addr_file = os.path.join(folder_path, f'tcp_addrs_{i}.txt')
    data_file = os.path.join(folder_path, f'tcp_data_{i}.dat')
    process_checksums(addr_file, data_file)