import struct


def get_ip_bytes(addresses):

    return bytes(map(int, addresses.split('.')))





def compute_checksum(data):
    if len(data) % 2 == 1:
        data += b'x00'

    for i in range(0, len(data), 2):

        total += int.from_bytes(data[i:i + 2], 'big')
        
        total = (total >> 16) + (total & 0xFFFF)

    return (~total) & 0xFFFF

# def gen_ip_pseudo_header(client_ip, dest_ip, tcp_length):
#     client_bytes = get_ip_bytes(client_ip)
#     dest_bytes = get_ip_bytes(dest_ip)


# test 
ip_text =  '1.1.1.1'

ip_address = get_ip_bytes(ip_text)

print(ip_address)


