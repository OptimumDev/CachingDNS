import socket

PORT = 53
ADDRESS = '127.0.0.1'
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


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ADDRESS, PORT))

while True:
    data, address = sock.recvfrom(SIZE)
    create_response(data)
