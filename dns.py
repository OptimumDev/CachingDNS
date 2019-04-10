import socket

PORT = 37000
ADDRESS = ''

DNS_PORT = 53
DNS_ADDRESS = '8.8.8.8'

SIZE = 512

A = b'\x00\x01'


def read_bits(byte, count):
    return ''.join([str(ord(byte) & (1 << bit)) for bit in range(1, count + 1)])


def str_bits_to_bytes(str_bits):
    return int(str_bits, 2).to_bytes(1, 'big')


def parse_type(request, name):
    name_end = 12 + len(name) + 2
    return request[name_end: name_end + 2]


def parse_flags(flags):
    qr = '1'
    opcode = read_bits(flags[:1], 4)
    aa = '1'
    tc = '0'
    rd = '0'
    ra = '0'
    z = '000'
    rcode = '0000'

    return str_bits_to_bytes(qr + opcode + aa + tc + rd) + str_bits_to_bytes(ra + z + rcode)


def parse_name(name):
    result = ''
    is_length = True
    length = 0
    current = 0

    for byte in name:
        if byte == 0:
            break

        if is_length:
            is_length = False
            length = byte
        elif current == length:
            result += '.'
            current = 0
            length = byte
        else:
            result += chr(byte)
            current += 1

    return result


def create_response(request):
    id = request[:2]
    flags = parse_flags(request[2:4])
    qdcount = b'\x00\x01'
    name = parse_name(request[12:])
    qtype = parse_type(request, name)
    ancount = b'\x00\x00'  # TODO get from base
    nscount = b'\x00\x00'  # ???
    arcount = b'\x00\x00'  # ???

    header = id + flags + qdcount + ancount + nscount + arcount
    print(header)


request_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
request_sock.bind((ADDRESS, DNS_PORT))

dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_sock.bind((ADDRESS, PORT))

while True:
    print('\nWAITING FOR REQUEST')
    data, address = request_sock.recvfrom(SIZE)
    print('\nGOT REQUEST')
    print(data)
    dns_sock.sendto(data, (DNS_ADDRESS, DNS_PORT))
    print('\nREDIRECTED')
    answer, _ = dns_sock.recvfrom(SIZE)
    print('\nGOT RESPONSE')
    print(answer)
    request_sock.sendto(answer, address)
    print('\nRESPONSE SENT')
