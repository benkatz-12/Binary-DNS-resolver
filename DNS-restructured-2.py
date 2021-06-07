import socket
import struct, binascii, pprint
 
def udp_dns(ip, port, domain, qname):
    #hardcoded header
    header = b'fedc01000001000000000000' 

    #build question section
    question = format_question(domain)
    qtype = translate_qname(qname)
   
    #build full message
    header += question
    null = b'00' #null terminator at the end of the QNAME section
    header += null
    header += qtype
    qclass = b'0001'  #QCLASS: (1) for internet class
    header += qclass
   
    qfull = binascii.unhexlify(header)
   
    data = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #intialize UDP socket
        sock.connect((ip, port))
        sock.send(qfull)
   
    except Exception as e:
        print(f"Exception - {e}")
        return -1
   
    #data = reciever(sock)

    data = sock.recv(1024)
   
    sock.close()
    decoded_data = binascii.hexlify(data).decode("utf-8")
    parse(decoded_data)
   
    return format_hex(binascii.hexlify(data).decode("utf-8"))
 
def reciever(sock):#does not work
    try:
        full_msg = b''
       
        msg = sock.recv(1024)
       
        while True:
            if msg is not None:
                full_msg += msg
                msg = sock.recv(1024)
                print('hre2')
                if len(msg) > 0:
                    print('Here1')
                    break
            if msg == 'Truncated':
                ...

    except Exception as e:
        print(e)
    print("here2")
    return full_msg

def format_question(domain):
    question = b''
    split = domain.split('.')
    for part in split:
        part_bits = part.encode('ascii')
        length = hex(len(part_bits)).encode('ascii')
        if len(length) == 3:
            length = length[2:].zfill(2)
        question += length
        question += binascii.hexlify(part_bits)
    return question
   
def format_hex(hex):
    """format_hex returns a pretty version of a hex string"""
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    pairs = [" ".join(octets[i:i+2]) for i in range(0, len(octets), 2)]
    return "\n".join(pairs)

def translate_qname(qname):
    
    qtranslator = {
        'A': b'0001',
        'NS': b'0002',
        'CNAME': b'0005',
        'SOA': b'0006',
        'PTR': b'000c', #NO TEST CASES
        'HINFO': b'000d', #NO TEST CASES
        'MX': b'000f',
        'TXT': b'0010', #issue with truncation
        'RP': b'0011', #NO TEST CASES
        'SIG': b'0018', #not implemented + NO TEST CASES + NEED TEST CASES
        'KEY': b'0019', #not implemented + NO TEST CASES + NEED TEST CASES
        'AAAA': b'001c',
        'SRV': b'0021', #NO TEST CASES
        'NAPTR': b'0023', #NO TEST CASES, REGEXP FIELD SPECIAL FORMATTING?? DDDS ALGO??
        'CERT': b'0025', #not implemented + MASSIVE RABBIT HOLE OF PARSING DIFFERENT CERTIFICATE TYPES??
        'DNAME': b'0027', #NO TEST CASES
        'DS': b'002b', #not implemented
        'SSHFP': b'002c', #not implemented
        'IPSECKEY': b'002d', #not implemented
        'RRSIG': b'002e', #not implemented
        'NSEC': b'002f', #not implemented
        'DNSKEY': b'0030', #not implemented
        'NSEC3': b'0032', #not implemented
        'NSEC3PARAM': b'0033', #not implemented
        'TLSA': b'0034', #not implemented
        'CDS': b'003b', #not implemented
        'SVCB': b'0040', #not implemented
        'HTTPS': b'0041', #not implemented
        'TSIG': b'00fa', #not implemented
        'CAA': b'0101' #not implemented
    }
    return qtranslator[qname]
def type_translator(type):
    record_types = {
        1 : 'A',
        2 : 'NS',
        5 : 'CNAME',
        6 : 'SOA',
        12 : 'PTR',
        13 : 'HINFO',
        15 : 'MX',
        16 : 'TXT',
        17 : 'RP',
        24 : 'SIG',
        25 : 'KEY',
        28 : 'AAAA',
        33 : 'SRV',
        35 : 'NAPTR',
        37 : 'CERT',
        39 : 'DNAME',
        43 : 'DS',
        44 : 'SSHFP',
        45 : 'IPSECKEY',
        46 : 'RRSIG',
        47 : 'NSEC',
        48 : 'DNSKEY',
        50 : 'NSEC3',
        51 : 'NSEC3PARAM',
        52 : 'TSLA',
        59 : 'CDS',
        64 : 'SVCB',
        65 : 'HTTPS',
        250 : 'TSIG',
        257 : 'CAA'
    }
   
    return record_types.get(type)

def parse_domain(cur_byte, data):
    pointer = False
    RDATA = {}
    RDATA["domain"] = ''
    LEN_SECTION = int(data[cur_byte : cur_byte+2], 16)
    cur_byte += 2
    while True:
        RDATA["domain"] += bytes.fromhex(data[cur_byte : cur_byte + LEN_SECTION*2]).decode("ascii")
        cur_byte += LEN_SECTION*2
        LEN_SECTION = int(data[cur_byte : cur_byte+2], 16)
        cur_byte += 2
        if LEN_SECTION == 0:
            RDATA["domain"] += '.'
            break
        elif LEN_SECTION == 192: #192=c0 means pointer to earlier text encoding
                pointer = True
                old_cur_byte = cur_byte + 2
                cur_byte = int(data[cur_byte : cur_byte+2], 16) * 2
                LEN_SECTION = int(data[cur_byte : cur_byte+2], 16)
                cur_byte += 2
        RDATA["domain"] += '.'
    if pointer:
        return RDATA["domain"], old_cur_byte
    return RDATA["domain"], cur_byte
def parse_char_string(CUR_BYTE, data):
    txt = ''
    string_length = int(data[CUR_BYTE : CUR_BYTE + 2], 16)
    CUR_BYTE += 2
    for a in range(string_length):
        txt += bytes.fromhex(data[CUR_BYTE : CUR_BYTE + 2]).decode("ascii")
        CUR_BYTE += 2
    return txt, CUR_BYTE

def A_parse(data, answer, CUR_BYTE):
    for z in range(answer["RDLENGTH"]*2-4):
        answer["RDATA"] += str(int(data[CUR_BYTE : CUR_BYTE+2], 16))
        CUR_BYTE += 2
        if z != answer["RDLENGTH"]*2-5: 
            answer["RDATA"] += '.'
    return answer, CUR_BYTE
def NS_parse(data, CUR_BYTE):
    ns_data = {}
    ns_data["NSDNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    return ns_data, CUR_BYTE
def CNAME_parse(data, CUR_BYTE):
    cname_data = {} 
    cname_data["CNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    return cname_data, CUR_BYTE
def SOA_parse(data, CUR_BYTE):
    soa_data = {}
    soa_data["MNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    soa_data["RNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    soa_data["SERIAL"] = data[CUR_BYTE : CUR_BYTE + 8]
    CUR_BYTE += 8
    soa_data["REFRESH"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
    CUR_BYTE += 8
    soa_data["RETRY"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
    CUR_BYTE += 8
    soa_data["EXPIRE"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
    CUR_BYTE += 8
    soa_data["MINIMUM"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
    CUR_BYTE += 8
    return soa_data, CUR_BYTE
def PTR_parse(data, CUR_BYTE):
    ptr_data = {}
    ptr_data["PTRDNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    return ptr_data, CUR_BYTE
def HINFO_parse(data, CUR_BYTE):
    hinfo_data = {}
    hinfo_data["CPU"] = ''
    hinfo_data["OS"] = ''
    string_length = int(data[CUR_BYTE : CUR_BYTE + 2], 16)
    CUR_BYTE += 2
    for a in range(string_length):
        hinfo_data["CPU"] += bytes.fromhex(data[CUR_BYTE : CUR_BYTE + 2]).decode("ascii")
        CUR_BYTE += 2
    string_length = int(data[CUR_BYTE : CUR_BYTE + 2], 16)
    CUR_BYTE += 2
    for a in range(string_length):
        hinfo_data["OS"] += bytes.fromhex(data[CUR_BYTE : CUR_BYTE + 2]).decode("ascii")
        CUR_BYTE += 2
    return hinfo_data, CUR_BYTE
def MX_parse(data, CUR_BYTE):
    mx_data = {}
    mx_data["PREFRENCE"] = int(data[CUR_BYTE : CUR_BYTE+4], 16)
    CUR_BYTE += 4
    mx_data["EXCHANGE"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    return mx_data, CUR_BYTE
def TXT_parse(data, CUR_BYTE):
    txt_data = {}
    txt_data["TXT-DATA"] = ''
    string_length = int(data[CUR_BYTE : CUR_BYTE + 2], 16)
    CUR_BYTE += 2
    for a in range(string_length):
        txt_data["TXT-DATA"] += bytes.fromhex(data[CUR_BYTE : CUR_BYTE + 2]).decode("ascii")
        CUR_BYTE += 2
    return txt_data, CUR_BYTE
def RP_parse(data, CUR_BYTE):
    rp_data = {}
    rp_data["mbox-dname"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    rp_data["txt-dname"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    return rp_data, CUR_BYTE
def AAAA_parse(data, CUR_BYTE):
    aaaa_data = {}
    aaaa_data["IPv6"] = ''
    for a in range(8):
        aaaa_data["IPv6"] += data[CUR_BYTE : CUR_BYTE+4].lstrip("0")
        CUR_BYTE += 4
        if a != 7: aaaa_data["IPv6"] += ':'
    return aaaa_data, CUR_BYTE
def SRV_parse(data, CUR_BYTE):
    srv_data = {}
    srv_data["Priority"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
    srv_data["Weight"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
    srv_data["Port"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
    srv_data["Target"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    return srv_data, CUR_BYTE
def NAPTR_parse(data, CUR_BYTE):
    naptr_data = {}
    naptr_data["ORDER"] = data[CUR_BYTE : CUR_BYTE + 4]
    CUR_BYTE += 4
    naptr_data["PREFRENCE"] = data[CUR_BYTE : CUR_BYTE + 4]
    CUR_BYTE += 4
    naptr_data["FLAGS"], CUR_BYTE = parse_char_string(CUR_BYTE, data)
    naptr_data["SERVICES"], CUR_BYTE = parse_char_string(CUR_BYTE, data)
    naptr_data["REGEXP"], CUR_BYTE = parse_char_string(CUR_BYTE, data)
    naptr_data["REPLACEMENT"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    return naptr_data, CUR_BYTE
def DNAME_parse(data, CUR_BYTE):
    dname_data = {}
    dname_data["TARGET"], CUR_BYTE = parse_domain(CUR_BYTE, data)
    return dname_data, CUR_BYTE

def header_parser(data):
    header = {}
    header["IDENT"] = data[0:4]
    flags = bin(int(data[4:8], 16))[2:]
    header["QR"] = flags[0] #0 for domain 1 for header
    header["OPCODE"] = int(flags[1:5])
    header["AA"] = flags[5]
    header["TC"] = flags[6]
   
    if header["TC"] == '1':
        raise ValueError('Truncated Message Error (dont handle yet)')
   
    header["RD"] = flags[7]
    header["RA"] = flags[8]
    header["RCODE"] = int(flags[12:17])
    header["QDCOUNT"] = int(data[8:12])
    header["ANCOUNT"] = int(data[12:16])
    header["NSCOUNT"] = int(data[16:20])
    header["ARCOUNT"] = int(data[20:24])
    CUR_BYTE = 24
    return header, CUR_BYTE
def question_parser(data, CUR_BYTE):
    question = {}
    question["QNAME"] = ''
    LEN_SECTION = int(data[CUR_BYTE : CUR_BYTE+2])
    CUR_BYTE += 2
    while True:
        question["QNAME"] += bytes.fromhex(data[CUR_BYTE : CUR_BYTE + LEN_SECTION*2]).decode("ascii")
        CUR_BYTE += LEN_SECTION*2
        LEN_SECTION = int(data[CUR_BYTE : CUR_BYTE+2], 16)
        CUR_BYTE += 2
        if LEN_SECTION == 0:
            break
        question["QNAME"] += '.'
    question["QTYPE"] = type_translator(int(data[CUR_BYTE : CUR_BYTE + 4], 16))
    CUR_BYTE += 4
    question["QCLASS"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
    CUR_BYTE += 4
    return question, CUR_BYTE
def record_parser(data, CUR_BYTE):
    answer = {}
    answer["name"] = ''
    if data[CUR_BYTE: CUR_BYTE + 2] == "c0": #code to follow pointer
        name_ptr = int(data[CUR_BYTE + 2: CUR_BYTE + 4], 16)*2
        LEN_SECTION = int(data[name_ptr : name_ptr+2]) #same code as above, move to function possibly?
        name_ptr += 2
        while True:
            answer["name"] += bytes.fromhex(data[name_ptr : name_ptr + LEN_SECTION*2]).decode("ascii")
            name_ptr += LEN_SECTION*2
            LEN_SECTION = int(data[name_ptr : name_ptr+2], 16)
            name_ptr += 2
            if LEN_SECTION == 0:
                break
            answer["name"] += '.'
    CUR_BYTE += 4
    answer["TYPE"] = type_translator(int(data[CUR_BYTE : CUR_BYTE + 4], 16))
    CUR_BYTE += 4
    answer["CLASS"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
    CUR_BYTE += 4
    answer["TTL"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
    CUR_BYTE += 8
    answer["RDLENGTH"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
    CUR_BYTE += 4
    answer["RDATA"] = ''
    if answer["TYPE"] == 'A':
        return A_parse(data, answer, CUR_BYTE)
    elif answer["TYPE"] == 'NS':
        answer["RDATA"], CUR_BYTE = NS_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'CNAME':
        answer["RDATA"], CUR_BYTE = CNAME_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'SOA':
        answer["RDATA"], CUR_BYTE = SOA_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'PTR':
        answer["RDATA"], CUR_BYTE = PTR_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'HINFO':
        answer["RDATA"] = HINFO_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'MX':
        answer["RDATA"], CUR_BYTE = MX_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'TXT': #truncation issue
        answer["RDATA"], CUR_BYTE = TXT_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'RP':
        answer["RDATA"], CUR_BYTE = RP_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'AAAA':
        answer["RDATA"], CUR_BYTE = AAAA_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'SRV':
        answer["RDATA"], CUR_BYTE = SRV_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'NAPTR':
        answer['RDATA'], CUR_BYTE = NAPTR_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    elif answer["TYPE"] == 'DNAME':
        answer["RDATA"], CUR_BYTE = DNAME_parse(data, CUR_BYTE)
        return answer, CUR_BYTE
    return answer, CUR_BYTE



def parse(data):
    response = {}

    response["header"], CUR_BYTE = header_parser(data)
   
    NUM_ANSWERS = response["header"]["ANCOUNT"]
    NUM_QUESTIONS = response["header"]["QDCOUNT"]
    NUM_AUTHORITY = response["header"]["NSCOUNT"]
    NUM_ADDITIONAL = response["header"]["ARCOUNT"]
 
    #parse question section
    for j in range(NUM_QUESTIONS):
        response["question-" + str(j)], CUR_BYTE = question_parser(data, CUR_BYTE)
 
    #parse answers
    for i in range(NUM_ANSWERS):
        response["answer-" + str(i)], CUR_BYTE = record_parser(data, CUR_BYTE)
 
    #parse authority
    for k in range(NUM_AUTHORITY):
        response["authority-" + str(k)], CUR_BYTE = record_parser(data, CUR_BYTE)
        NUM_ADDITIONAL-=1

    #parse additional
    for m in range(NUM_ADDITIONAL):
        response["additional-" + str(m)], CUR_BYTE = record_parser(data, CUR_BYTE)

    pprint.pprint(response)




if __name__ == "__main__":
   
    qname = 'DNAME'   
    ip = "8.8.8.8"
   
    domain = "saep.io"
    #domain = "twitch.tv"
    #domain = "test.quantreads.com"
   
    port = 53
    udp_dns(ip, port, domain, qname)