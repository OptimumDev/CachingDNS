import socket

BYTE_ORDER = 'big'

PORT = 37000
ADDRESS = ''

DNS_PORT = 53
# DNS_ADDRESS = '8.8.8.8'
DNS_ADDRESS = 'ns1.e1.ru'

SIZE = 512

A = b'\x00\x01'
NS = b'\x00\x02'

DATA = {
    A: {},
    NS: {}
}


def read_bits(byte, count):
    return ''.join([str(ord(byte) & (1 << bit)) for bit in range(1, count + 1)])


def str_bits_to_bytes(str_bits):
    str_bits = str_bits.replace(' ', '')
    length = len(str_bits) // 8
    return int(str_bits, 2).to_bytes(length, BYTE_ORDER)


def parse_type(type):
    return type[:2]


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


def parse_name_part(name):
    length = name[0]
    result = ''
    for i in range(length):
        result += chr(name[i + 1])
    return result


def parse_name(data, name_start):
    name = data[name_start:]
    a = name[0]
    current = 0
    parts = []

    while name[current] != 0:
        if name[current] & 192 == 192:
            link = int.from_bytes(name[current:current + 2], BYTE_ORDER) & int('0011111111111111', 2)
            name_end, _ = parse_name(data, link)
            parts.append(name_end)
            current += 1
            break
        part = parse_name_part(name[current:])
        parts.append(part)
        current += len(part) + 1

    result_name = '.'.join(parts)
    return result_name, name_start + current + 1


def parse_answer_records_number(data):
    answers = int.from_bytes(data[6:8], BYTE_ORDER)
    authority = int.from_bytes(data[8:10], BYTE_ORDER)
    additional = int.from_bytes(data[10:12], BYTE_ORDER)
    print ('answers', answers, authority, additional)
    return answers + authority + additional


def parse_answer_record(data, record_start):
    name, type_start = parse_name(data, record_start)

    ttl_start = type_start + 4
    data_length_start = ttl_start + 4
    data_start = data_length_start + 2

    type = parse_type(data[type_start:])
    a = data[type_start:]

    if type not in DATA:
        return '', '', 0, '', 0

    ttl = int.from_bytes(data[ttl_start: data_length_start], BYTE_ORDER)
    record_data_length = int.from_bytes(data[data_length_start: data_start], BYTE_ORDER)
    record_data = data[data_start: data_start + record_data_length]

    if type == NS:
        record_data = parse_name(data, data_start)[0]

    return name, type, ttl, record_data, data_start + record_data_length


def parse_request(request):
    id = request[:2]
    name, type_start = parse_name(request, 12)
    type = parse_type(request[type_start:])
    next_block_start = type_start + 4
    print(name, 'type =', 'A' if type == A else 'NS' if type == NS else type)
    return id, name, type, next_block_start


def create_response(id, name, type):
    return b''


def add_record_to_cache(type, name, ttl, data):
    if name not in DATA[type]:
        DATA[type][name] = []
    DATA[type][name].append((ttl, data))


def cache_response(response):
    _, name, type, next_block_start = parse_request(response)
    records_count = parse_answer_records_number(response)
    for i in range(records_count):
        name, type, ttl, data, next_block_start = parse_answer_record(response, next_block_start)
        if type not in DATA:
            print('unknown type', type)
            return
        add_record_to_cache(type, name, ttl, data)
        print('CACHED', name, type, ttl, data)


def process_known_request(request_sock, address, id, name, type):
    answer = create_response(id, name, type)
    request_sock.sendto(answer, address)


def process_unknown_request(dns_sock, request_sock, request, address):
    dns_sock.sendto(request, (DNS_ADDRESS, DNS_PORT))
    print('\nREDIRECTED')

    answer, _ = dns_sock.recvfrom(SIZE)
    print('\nGOT RESPONSE')

    cache_response(answer)
    print('\nRESPONSE CACHED')

    request_sock.sendto(answer, address)


def run_dns():
    request_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    request_sock.bind((ADDRESS, DNS_PORT))

    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.bind((ADDRESS, PORT))

    while True:
        print('\nWAITING FOR REQUEST')

        request, address = request_sock.recvfrom(SIZE)
        print('\nGOT REQUEST')

        id, name, type, _ = parse_request(request)

        if type not in DATA:
            print('UNKNOWN TYPE', type)
            continue

        # if name in DATA[type]:
        #     print('KNOWN')
        #     process_known_request(request_sock, address, id, name, type)
        # else:
        print('UNKNOWN')
        process_unknown_request(dns_sock, request_sock, request, address)

        print('\nRESPONSE SENT')


if __name__ == '__main__':
    run_dns()
