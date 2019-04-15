import argparse
import os
import socket
import time
import threading

BYTE_ORDER = 'big'


PORT = 37000
ADDRESS = ''

DNS_PORT = 53

SIZE = 512

A = b'\x00\x01'
NS = b'\x00\x02'

DATA = {
    A: {},
    NS: {}
}

TYPE_NAMES = {
    A: 'A',
    NS: 'NS'
}


def not_logging(*args):
    pass


LOG = not_logging


def get_type_name(type):
    return TYPE_NAMES[type] if type in TYPE_NAMES else type


def read_bits(byte, count):
    return ''.join([str(ord(byte) & (1 << bit)) for bit in range(1, count + 1)])


def str_bits_to_bytes(str_bits):
    str_bits = str_bits.replace(' ', '')
    length = len(str_bits) // 8
    return int(str_bits, 2).to_bytes(length, BYTE_ORDER)


def parse_type(type, type_start):
    return type[type_start: type_start + 2]


def get_flags(request):
    qr = int('10000000', 2)
    opcode = request[2] & int('01111000', 2)
    aa = int('00000100', 2)
    tc = rd = ra = z = rcode = 0
    return (qr + opcode + aa + tc + rd).to_bytes(1, BYTE_ORDER) + (ra + z + rcode).to_bytes(1, BYTE_ORDER)


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
    current = 0
    parts = []
    link_pattern = int('11000000', 2)

    while name[current] != 0:
        if name[current] & link_pattern == link_pattern:
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


def encode_name(name):
    result = b''
    parts = name.split('.')
    for part in parts:
        result += len(part).to_bytes(1, BYTE_ORDER)
        for char in part:
            result += ord(char).to_bytes(1, BYTE_ORDER)
    result += (0).to_bytes(1, BYTE_ORDER)
    return result


def parse_answer_records_number(data):
    answers = int.from_bytes(data[6:8], BYTE_ORDER)
    authority = int.from_bytes(data[8:10], BYTE_ORDER)
    additional = int.from_bytes(data[10:12], BYTE_ORDER)
    LOG('records:', answers, authority, additional)
    return answers + authority + additional


def parse_answer_record(data, record_start):
    name, type_start = parse_name(data, record_start)

    ttl_start = type_start + 4
    data_length_start = ttl_start + 4
    data_start = data_length_start + 2

    type = parse_type(data, type_start)

    if type not in DATA:
        LOG('unknown type', get_type_name(type))
        return '', '', 0, '', 0

    ttl = int.from_bytes(data[ttl_start: data_length_start], BYTE_ORDER)
    record_data_length = int.from_bytes(data[data_length_start: data_start], BYTE_ORDER)
    record_data = data[data_start: data_start + record_data_length]

    if type == NS:
        record_data = parse_name(data, data_start)[0]

    return name, type, ttl, record_data, data_start + record_data_length


def encode_record(record, expire_time, type, name):
    encoded_name = encode_name(name)
    cls = (1).to_bytes(2, BYTE_ORDER)
    time_left = int(expire_time - time.time())
    ttl = time_left.to_bytes(4, BYTE_ORDER)
    rdata = record if type == A else encode_name(record)
    rdlength = len(rdata).to_bytes(2, BYTE_ORDER)

    LOG('record:', name, get_type_name(type), time_left, len(rdata), record)
    return encoded_name + type + cls + ttl + rdlength + rdata


def get_query_record(name, type):
    encoded_name = encode_name(name)
    return encoded_name + type + (1).to_bytes(2, BYTE_ORDER)


def get_cached_recods(name, type):
    result = []
    for time in DATA[type][name]:
        for record in DATA[type][name][time]:
            result.append((time, record))
    return result


def get_answer_records(name, type):
    records = get_cached_recods(name, type)
    result = b''

    LOG('records:', len(records), 0, 0)

    for record in records:
        result += encode_record(record[1], record[0], type, name)
    return result


def parse_request(request):
    id = request[:2]
    name, type_start = parse_name(request, 12)
    type = parse_type(request, type_start)
    next_block_start = type_start + 4
    LOG(name, 'type =', get_type_name(type))
    return id, name, type, next_block_start


def create_response(id, name, type, request):
    LOG(name, 'type =', get_type_name(type))

    flasgs = get_flags(request)
    records = get_answer_records(name, type)
    qdcount = (1).to_bytes(2, BYTE_ORDER)
    ancount = len(get_cached_recods(name, type)).to_bytes(2, BYTE_ORDER)
    nscount = arcount = (0).to_bytes(2, BYTE_ORDER)
    query = get_query_record(name, type)

    return id + flasgs + qdcount + ancount + nscount + arcount + query + records


def add_record_to_cache(type, name, ttl, data):
    expire_time = time.time() + ttl
    if name not in DATA[type]:
        DATA[type][name] = {}
    if expire_time not in DATA[type][name]:
        DATA[type][name][expire_time] = []
    DATA[type][name][expire_time].append(data)


def cache_response(response):
    _, name, type, next_block_start = parse_request(response)
    records_count = parse_answer_records_number(response)
    for i in range(records_count):
        name, type, ttl, data, next_block_start = parse_answer_record(response, next_block_start)
        if type not in DATA:
            return
        add_record_to_cache(type, name, ttl, data)
        LOG('cached:', name, get_type_name(type), ttl, len(data), data)


def process_known_request(request_sock, address, id, name, type, request):
    LOG('\nCREATING RESPONSE')
    response = create_response(id, name, type, request)
    LOG('RESPONSE CREATED')
    request_sock.sendto(response, address)


def process_unknown_request(dns_sock, base_ip, request_sock, request, address):
    dns_sock.sendto(request, (base_ip, DNS_PORT))
    LOG('\nREDIRECTED')

    response, _ = dns_sock.recvfrom(SIZE)
    LOG('\nGOT RESPONSE')

    cache_response(response)
    LOG('RESPONSE CACHED')

    request_sock.sendto(response, address)


def have_cached_records(name, type):
    if name not in DATA[type]:
        return False
    records = DATA[type][name]
    not_expired_records = {}
    for record in records:
        if record > time.time():
            not_expired_records[record] = records[record]
    DATA[type][name] = not_expired_records
    return len(not_expired_records) > 0


def run_dns(base_ip):
    request_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    request_sock.bind((ADDRESS, DNS_PORT))

    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.bind((ADDRESS, PORT))

    while True:
        LOG('\nWAITING FOR REQUEST')

        request, address = request_sock.recvfrom(SIZE)
        LOG('\nGOT REQUEST')

        id, name, type, _ = parse_request(request)

        if type not in DATA:
            LOG('UNKNOWN TYPE', type)
            continue

        if have_cached_records(name, type):
            LOG('CACHED')
            process_known_request(request_sock, address, id, name, type, request)
        else:
            LOG('NOT CACHED')
            process_unknown_request(dns_sock, base_ip, request_sock, request, address)

        LOG('\nRESPONSE SENT')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Caching DNS server')
    parser.add_argument('base_server_ip', metavar='IP', help='ip address of base DNS server')
    parser.add_argument('-l', '--logging_on', action='store_true')

    args = parser.parse_args()
    if args.logging_on:
        LOG = print
    check_command = 'ping -n 1 ' + args.base_server_ip + ' > nul'
    if os.system(check_command) != 0:
        parser.error(f'base server (by IP: {args.base_server_ip}) is unreachable')

    threading.Thread(target=run_dns, args=(args.base_server_ip,), daemon=True).start()
    print(f'\nRunning server on IP: {args.base_server_ip}')
    print('Press Enter to exit')
    _ = input()
