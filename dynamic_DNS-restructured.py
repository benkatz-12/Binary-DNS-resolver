import socket
import struct, binascii, pprint

dnssec = ["RRSIG", "DNSKEY", "DS", "NSEC", "NSEC3", "CDS", "CDNKEY"]
OPT_rr = b'000041100000800000'


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
   
    if qtype in dnssec:
        additional = OPT_rr
        header = b'fedc01000001000000000001'
        header += question
        null = b'00' #null terminator at the end of the QNAME section
        header += null
        header += qtype
        qclass = b'0001'  #QCLASS: (1) for internet class
        header += qclass
        header += additional

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
        'DNAME': b'0027', #NO TEST CASES
        'RP': b'0011', #NO TEST CASES
        'SRV': b'0021', #NO TEST CASES
        'NAPTR': b'0023', #NO TEST CASES, REGEXP FIELD SPECIAL FORMATTING?? DDDS ALGO??
        'TXT': b'0010', #issue with truncation
        'MX': b'000f',
        'AAAA': b'001c',
        'KEY': b'0019', #not implemented + NO TEST CASES + NEED TEST CASES
        'SIG': b'0018', #not implemented + NO TEST CASES + NEED TEST CASES
        'CERT': b'0025', #not implemented + NO TEST CASES + NEED TEST CASES
        'DS': b'002b', 
        'SSHFP': b'002c', #not implemented + DNSSEC RABBIT HOLE
        'IPSECKEY': b'002d', #not implemented
        'RRSIG': b'002e', #not implemented+ DNSSEC RABBIT HOLE //
        'NSEC': b'002f',
        'DNSKEY': b'0030', #not implemented+ DNSSEC RABBIT HOLE // Cloudflare.com  NEXT UP ASF;LASIJFAOW;IJFA;OIF
        'NSEC3': b'0032', #not implemented+ DNSSEC RABBIT HOLE
        'NSEC3PARAM': b'0033', #not implemented
        'TLSA': b'0034', #not implemented // Cloudflare.com
        'CDS': b'003b',
        'SVCB': b'0040', #not implemented
        'HTTPS': b'0041', #not implemented // Cloudflare.com // not implemented with dig or host commands
        'TSIG': b'00fa', #not implemented //Cloudflare.com
        'CAA': b'0101' #not implemented
    }
    return qtranslator[qname]
def type_translator(type):
    record_types = {
        0 : "NONE",
        1 : "A",
        2 : "NS",
        3 : "MD",
        4 : "MF",
        5 : "CNAME",
        6 : "SOA",
        7 : "MB",
        8 : "MG",
        9 : "MR",
        10 : "NULL",
        11 : "WKS",
        12 : "PTR",
        13 : "HINFO",
        14 : "MINFO",
        15 : "MX",
        16 : "TXT",
        17 : "RP",
        18 : "AFSDB",
        19 : "X25",
        20 : "ISDN",
        21 : "RT",
        22 : "NSAP",
        23 : "NSAP_PTR",
        24 : "SIG",
        25 : "KEY",
        26 : "PX",
        27 : "GPOS",
        28 : "AAAA",
        29 : "LOC",
        30 : "NXT",
        31 : "EID",
        32 : "NIMLOC",
        33 : "SRV",
        34 : "ATMA",
        35 : "NAPTR",
        36 : "KX",
        37 : "CERT",
        38 : "A6",
        39 : "DNAME",
        41 : "OPT",
        42 : "APL",
        43 : "DS",
        44 : "SSHFP",
        45 : "IPSECKEY",
        46 : "RRSIG",
        47 : "NSEC",
        48 : "DNSKEY",
        49 : "DHCID",
        50 : "NSEC3",
        51 : "NSEC3PARAM",
        52 : "TLSA",
        53 : "SMIMEA",
        55 : "HIP",
        56 : "NINFO",
        57 : "RKEY",
        58 : "TALINK",
        59 : "CDS",
        60 : "CDNSKEY",
        61 : "OPENPGPKEY",
        62 : "CSYNC",
        63 : "ZONEMD",
        64 : "SVCB",
        65 : "HTTPS",
        99 : "SPF",
        100 : "UINFO",
        101 : "UID",
        102 : "GID",
        103 : "UNSPEC",
        104 : "NID",
        105 : "L32",
        106 : "L64",
        107 : "LP",
        108 : "EUI48",
        109 : "EUI64",
        249 : "TKEY",
        250 : "TSIG",
        251 : "IXFR",
        252 : "AXFR",
        253 : "MAILB",
        254 : "MAILA",
        255 : "ANY",
        256 : "URI",
        257 : "CAA",
        258 : "AVC",
        259 : "DOA",
        260 : "AMTRELAY",
        32768 : "TA",
        32769 : "DLV"
    }
   
    return record_types.get(type)
def translate_rcode(rcode):
    codes = {
        0 : "NoError",
        1 : "FormErr",
        2 : "ServFail",
        3 : "NXDomain",
        4 : "NotImp",
        5 : "Refused",
        6 : "YXDomain",
        7 : "YXRRSet",
        8 : "NXRRSet",
        9 : "NotAuth",
        10 : "NotZone",
        11 : "DSOTYPENI",
        16 : "BADVERS // BADSIG",
        17 : "BADKEY",
        18 : "BADTIME",
        19 : "BADMODE",
        20 : "BADNAME",
        21 : "BADALG",
        22 : "BADTRUNC",
        23 : "BADCOOKIE"
    }
    return codes[int(rcode, 16)]
def translate_algo_type(value):
    algos = {
        0 : "Delete DS",
        1 : "RSA/MD5",
        2 : "Diffie-Hellman",
        3 : "DSA/SHA-1",
        4 : "Elliptic Curve",
        5 : "RSA/SHA-1",
        6 : "DSA-NSEC3-SHA1",
        7 : "RSASHA1-NSEC3-SHA1",
        8 : "RSA/SHA-256",
        9 : "reserved",
        10 : "RSA/SHA-512",
        11 : "reserved",
        12 : "GOST R 34.10-2001",
        13 : "ECDSA Curve P-256 with SHA-256",
        14 : "ECDSA Curve P-384 with SHA-384",
        15 : "Ed25519",
        16 : "Ed448",
        252 : "Indirect",
        253 : "Private [DNS]",
        254 : "Private [OID]",
        255 : "Reserved"
    }
    return algos[value]
def translate_digest_type(value):
    digest = {
        0 : "reserved",
        1 : "SHA-1",
        2 : "SHA-256",
        3 : "GOST R 34.11-94",
        4 : "SHA-384"
    }
    return digest[value]

def parse_domain(current_byte, data):
    pointer = False
    RDATA = {}
    RDATA["domain"] = ''
    LEN_SECTION = int(data[current_byte : current_byte+2], 16)
    current_byte += 2
    while True:
        RDATA["domain"] += bytes.fromhex(data[current_byte : current_byte + LEN_SECTION*2]).decode("ascii")
        current_byte += LEN_SECTION*2
        LEN_SECTION = int(data[current_byte : current_byte+2], 16)
        current_byte += 2
        if LEN_SECTION == 0:
            RDATA["domain"] += '.'
            break
        elif LEN_SECTION == 192: #192=c0 means pointer to earlier text encoding
                pointer = True
                old_current_byte = current_byte + 2
                current_byte = int(data[current_byte : current_byte+2], 16) * 2
                LEN_SECTION = int(data[current_byte : current_byte+2], 16)
                current_byte += 2
        RDATA["domain"] += '.'
    if pointer:
        return RDATA["domain"], old_current_byte
    return RDATA["domain"], current_byte
def parse_char_string(current_byte, data):
    txt = ''
    string_length = int(data[current_byte : current_byte + 2], 16)
    current_byte += 2
    for a in range(string_length):
        txt += bytes.fromhex(data[current_byte : current_byte + 2]).decode("ascii")
        current_byte += 2
    return txt, current_byte
def parse_type_bitmap(current_byte, data):
    types = []
    while True:
        try:
            window = int(data[current_byte : current_byte+2], 16)
            current_byte += 2
            data_len = int(data[current_byte : current_byte+2], 16)
            current_byte += 2
            bit_map = bin(int(data[current_byte : current_byte + data_len*2], 16))[2:].zfill(data_len*8)
            current_byte += data_len*2
            for i in range(len(bit_map)):
                if bit_map[i] == '1':
                    types.append(type_translator((window*256)+i))
        except Exception as e:
            break

    
    return types, current_byte

def A_parse(data, current_byte, answer):
    for z in range(answer["RDLENGTH"]*2-4):
        answer["RDATA"] += str(int(data[current_byte : current_byte+2], 16))
        current_byte += 2
        if z != answer["RDLENGTH"]*2-5: 
            answer["RDATA"] += '.'
    return answer, current_byte

def NS_parse(data, current_byte, answer):
    ns_data = {}
    ns_data["NSDNAME"], current_byte = parse_domain(current_byte, data)
    answer["RDATA"] = ns_data
    return answer, current_byte

def CNAME_parse(data, current_byte, answer):
    cname_data = {}
    cname_data["CNAME"], current_byte = parse_domain(current_byte, data)
    answer["RDATA"] = cname_data
    return answer, current_byte

def SOA_parse(data, current_byte, answer):
    soa_data = {}
    soa_data["MNAME"], current_byte = parse_domain(current_byte, data)
    soa_data["RNAME"], current_byte = parse_domain(current_byte, data)
    soa_data["SERIAL"] = data[current_byte : current_byte + 8]
    current_byte += 8
    soa_data["REFRESH"] = int(data[current_byte : current_byte + 8], 16)
    current_byte += 8
    soa_data["RETRY"] = int(data[current_byte : current_byte + 8], 16)
    current_byte += 8
    soa_data["EXPIRE"] = int(data[current_byte : current_byte + 8], 16)
    current_byte += 8
    soa_data["MINIMUM"] = int(data[current_byte : current_byte + 8], 16)
    current_byte += 8
    answer["RDATA"] = soa_data
    return answer, current_byte

def PTR_parse(data, current_byte, answer):
    ptr_data = {}
    ptr_data["PTRDNAME"], current_byte = parse_domain(current_byte, data)
    answer["RDATA"] = ptr_data
    return answer, current_byte

def HINFO_parse(data, current_byte, answer):
    hinfo_data = {}
    hinfo_data["CPU"], current_byte = parse_char_string(current_byte, data)
    hinfo_data["OS"], current_byte = parse_char_string(current_byte, data)
    # hinfo_data["CPU"] = ''
    # hinfo_data["OS"] = ''
    # string_length = int(data[current_byte : current_byte + 2], 16)
    # current_byte += 2
    # for a in range(string_length):
    #     hinfo_data["CPU"] += bytes.fromhex(data[current_byte : current_byte + 2]).decode("ascii")
    #     current_byte += 2
    # string_length = int(data[current_byte : current_byte + 2], 16)
    # current_byte += 2
    # for a in range(string_length):
    #     hinfo_data["OS"] += bytes.fromhex(data[current_byte : current_byte + 2]).decode("ascii")
    #     current_byte += 2
    answer["RDATA"] = hinfo_data
    return answer, current_byte

def MX_parse(data, current_byte, answer):
    mx_data = {}
    mx_data["PREFRENCE"] = int(data[current_byte : current_byte+4], 16)
    current_byte += 4
    mx_data["EXCHANGE"], current_byte = parse_domain(current_byte, data)
    answer["RDATA"] = mx_data
    return mx_data, current_byte

def TXT_parse(data, current_byte, answer):
    txt_data = {}
    txt_data["TXT-DATA"], current_byte = parse_char_string(current_byte, data)
    answer["RDATA"] = txt_data
    return answer, current_byte

def RP_parse(data, current_byte, answer):
    rp_data = {}
    rp_data["mbox-dname"], current_byte = parse_domain(current_byte, data)
    rp_data["txt-dname"], current_byte = parse_domain(current_byte, data)
    answer["RDATA"] = rp_data
    return rp_data, current_byte

def AAAA_parse(data, current_byte, answer):
    aaaa_data = {}
    aaaa_data["IPv6"] = ''
    for a in range(8):
        aaaa_data["IPv6"] += data[current_byte : current_byte+4].lstrip("0")
        current_byte += 4
        if a != 7: aaaa_data["IPv6"] += ':'
    answer["RDATA"] = aaaa_data
    return answer, current_byte

def SRV_parse(data, current_byte, answer):
    srv_data = {}
    srv_data["Priority"] = int(data[current_byte : current_byte + 4], 16)
    srv_data["Weight"] = int(data[current_byte : current_byte + 4], 16)
    srv_data["Port"] = int(data[current_byte : current_byte + 4], 16)
    srv_data["Target"], current_byte = parse_domain(current_byte, data)
    answer["RDATA"] = srv_data
    return answer, current_byte

def NAPTR_parse(data, current_byte, answer):
    naptr_data = {}
    naptr_data["ORDER"] = data[current_byte : current_byte + 4]
    current_byte += 4
    naptr_data["PREFRENCE"] = data[current_byte : current_byte + 4]
    current_byte += 4
    naptr_data["FLAGS"], current_byte = parse_char_string(current_byte, data)
    naptr_data["SERVICES"], current_byte = parse_char_string(current_byte, data)
    naptr_data["REGEXP"], current_byte = parse_char_string(current_byte, data)
    naptr_data["REPLACEMENT"], current_byte = parse_domain(current_byte, data)
    answer["RDATA"] = naptr_data
    return answer, current_byte

def DNAME_parse(data, current_byte, answer):
    dname_data = {}
    dname_data["TARGET"], current_byte = parse_domain(current_byte, data)
    answer["RDATA"] = dname_data
    return answer, current_byte

def DNSKEY_parse(data, current_byte, answer):
    dnskey_data = {}
    dnskey_data["FLAGS"] = data[current_byte : current_byte + 2] #flag 7 and flag 15
    current_byte+= 2
    dnskey_data["PROTOCOL"] = int(data[current_byte : current_byte + 1], 16)
    current_byte+= 1
    if dnskey_data["PROTOCOL"] != 3:
        ...
        #raise ValueError("DNSKEY protocol field needs to be 3, it is " , dnskey_data["PROTOCOL"])
    dnskey_data["ALGORITHM"] = data[current_byte : current_byte + 1]
    current_byte+= 1
    answer["RDATA"] = dnskey_data
    return answer, current_byte

def DS_parse(data, current_byte, answer):
    ds_data = {}
    msg_len = int(data[current_byte - 4 : current_byte], 16)
    ds_data["Key Tag"] = data[current_byte : current_byte + 4] #compute key tag in order to match to DNSKEY tag
    current_byte += 4
    ds_data["Algorithm"] = translate_algo_type(int(data[current_byte : current_byte + 2], 16)) + ' (' + str(int(data[current_byte : current_byte + 2], 16)) + ')'
    current_byte += 2
    ds_data["Digest Type"] = translate_digest_type(int(data[current_byte : current_byte + 2], 16)) + ' (' + str(int(data[current_byte : current_byte + 2], 16)) + ')'
    current_byte += 2
    ds_data["Digest"] = data[current_byte : current_byte + (msg_len-4)*2]
    current_byte += (msg_len-4)*2
    answer["RDATA"] = ds_data
    return answer, current_byte

def CDS_parse(data, current_byte, answer):
    cds_data = {}
    msg_len = int(data[current_byte - 4 : current_byte], 16)
    cds_data["Key Tag"] = data[current_byte : current_byte + 4] #compute key tag in order to match to DNSKEY tag
    current_byte += 4
    cds_data["Algorithm"] = translate_algo_type(int(data[current_byte : current_byte + 2], 16)) + ' (' + str(int(data[current_byte : current_byte + 2], 16)) + ')'
    current_byte += 2
    cds_data["Digest Type"] = translate_digest_type(int(data[current_byte : current_byte + 2], 16)) + ' (' + str(int(data[current_byte : current_byte + 2], 16)) + ')'
    current_byte += 2
    cds_data["Digest"] = data[current_byte : current_byte + (msg_len-4)*2]
    current_byte += (msg_len-4)*2
    answer["RDATA"] = cds_data
    return answer, current_byte

def NSEC_parse(data, current_byte, answer):
    nsec_data = {}
    nsec_data["Next Domain Name"], current_byte = parse_domain(current_byte, data)
    nsec_data["Types"], current_byte = parse_type_bitmap(current_byte, data)
    answer["RDATA"] = nsec_data
    return answer, current_byte

def header_parser(data):
    header = {}
    header["IDENT"] = data[0:4]
    flags = bin(int(data[4:8], 16))[2:]
    header["QR"] = flags[0] #0 for domain 1 for header
    header["OPCODE"] = int(flags[1:5])
    header["AA"] = flags[5]
    header["TC"] = flags[6]
   
    if header["TC"] == '1':
        raise ValueError('Truncated Message Error (need TCP connection)')
   
    header["RD"] = flags[7]
    header["RA"] = flags[8]
    header["RCODE"] = translate_rcode(flags[12:17])
    header["QDCOUNT"] = int(data[8:12])
    header["ANCOUNT"] = int(data[12:16])
    header["NSCOUNT"] = int(data[16:20])
    header["ARCOUNT"] = int(data[20:24])
    current_byte = 24
    return header, current_byte

def question_parser(data, current_byte):
    question = {}
    question["QNAME"] = ''
    LEN_SECTION = int(data[current_byte : current_byte+2], 16)
    current_byte += 2
    while True:
        question["QNAME"] += bytes.fromhex(data[current_byte : current_byte + LEN_SECTION*2]).decode("ascii")
        current_byte += LEN_SECTION*2
        LEN_SECTION = int(data[current_byte : current_byte+2], 16)
        current_byte += 2
        if LEN_SECTION == 0:
            break
        question["QNAME"] += '.'
    question["QTYPE"] = type_translator(int(data[current_byte : current_byte + 4], 16))
    current_byte += 4
    question["QCLASS"] = int(data[current_byte : current_byte + 4], 16)
    current_byte += 4
    return question, current_byte

def eval_rr(rtype):
    d = {
    "A": A_parse,
    "NS": NS_parse,
    "CNAME": CNAME_parse,
    "SOA": SOA_parse,
    "PTR": PTR_parse,
    "HINFO": HINFO_parse,
    "MX": MX_parse,
    "TXT": TXT_parse,
    "RP": RP_parse,
    "AAAA": AAAA_parse,
    "SRV": SRV_parse,
    "NAPTR": NAPTR_parse,
    "DNAME": DNAME_parse,
    "DNSKEY": DNSKEY_parse,
    "DS" : DS_parse,
    "CDS" : CDS_parse,
    "NSEC" : NSEC_parse
    }

    func = d[rtype]
    return func

def record_parser(data, current_byte):
    answer = {}
    answer["name"] = ''
    if data[current_byte: current_byte + 2] == "c0": #code to follow pointer
        name_ptr = int(data[current_byte + 2: current_byte + 4], 16)*2
        LEN_SECTION = int(data[name_ptr : name_ptr+2], 16) #same code as above, move to function possibly?
        name_ptr += 2
        while True:
            answer["name"] += bytes.fromhex(data[name_ptr : name_ptr + LEN_SECTION*2]).decode("ascii")
            name_ptr += LEN_SECTION*2
            LEN_SECTION = int(data[name_ptr : name_ptr+2], 16)
            name_ptr += 2
            if LEN_SECTION == 0:
                break
            answer["name"] += '.'
    current_byte += 4
    answer["TYPE"] = type_translator(int(data[current_byte : current_byte + 4], 16))
    current_byte += 4
    answer["CLASS"] = int(data[current_byte : current_byte + 4], 16)
    current_byte += 4
    answer["TTL"] = int(data[current_byte : current_byte + 8], 16)
    current_byte += 8
    answer["RDLENGTH"] = int(data[current_byte : current_byte + 4], 16)
    current_byte += 4
    answer["RDATA"] = ''

    return eval_rr(answer["TYPE"])(data, current_byte, answer)

def parse(data):
    response = {}

    response["header"], current_byte = header_parser(data)
   
    NUM_ANSWERS = response["header"]["ANCOUNT"]
    NUM_QUESTIONS = response["header"]["QDCOUNT"]
    NUM_AUTHORITY = response["header"]["NSCOUNT"]
    NUM_ADDITIONAL = response["header"]["ARCOUNT"]
 
    #parse question section
    for j in range(NUM_QUESTIONS):
        response["question-" + str(j)], current_byte = question_parser(data, current_byte)
 
    #parse answers
    for i in range(NUM_ANSWERS):
        response["answer-" + str(i)], current_byte = record_parser(data, current_byte)
 
    #parse authority
    for k in range(NUM_AUTHORITY):
        response["authority-" + str(k)], current_byte = record_parser(data, current_byte)
        NUM_ADDITIONAL-=1

    #parse additional
    for m in range(NUM_ADDITIONAL):
        response["additional-" + str(m)], current_byte = record_parser(data, current_byte)

    pprint.pprint(response)




if __name__ == "__main__":
   
    qname = 'NSEC'   
    ip = "8.8.8.8"
   
    #domain = "saep.io"
    #domain = "twitch.tv"
    #domain = "test.quantreads.com"
    domain = "cloudflare.com"
   
    port = 53
    udp_dns(ip, port, domain, qname)