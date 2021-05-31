import socket
import struct, binascii, pprint
 
def udp_dns(ip, port, domain, qname):
    header = b'fedc01000001000000000000' 

    question = format_question(domain)
    qtype = translate_qname(qname)
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
    data = sock.recv(1024)
    while(1):
        if data is not None:
            if len(data) > 0:
                break
    sock.close()
    parse(binascii.hexlify(data).decode("utf-8"))
    return format_hex(binascii.hexlify(data).decode("utf-8"))
 
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
        'PTR': b'000c', #havent tested
        'HINFO': "",
        'MX': b'000f',
        'TXT': b'0010', #issue with truncation
        'RP': "",
        'SIG': "",
        'KEY': "",
        'AAAA': "",
        'SRV': "",
        'NAPTR': "",
        'CERT': "",
        'DNAME': "",
        'DS': "",
        'SSHFP': "",
        'IPSECKEY': "",
        'RRSIG': "",
        'NSEC': "",
        'DNSKEY': "",
        'NSEC3': "",
        'NSEC3PARAM': "",
        'TLSA': "",
        'CDS': "",
        'SVCB': "",
        'HTTPS': "",
        'TSIG': "",
        'CAA': ""
    }
    return qtranslator[qname]
def parse(data):
    response = {}
 
    #parse header
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
    response["header"] = header
    NUM_ANSWERS = header["ANCOUNT"]
    NUM_QUESTIONS = header["QDCOUNT"]
    CUR_BYTE = 24
 
    #parse question section
    question = {}
    for j in range(NUM_QUESTIONS):
        question["QNAME"] = ''
        #CUR_BYTE = CUR_BYTE * (j+1)
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
        question["QTYPE"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
        CUR_BYTE += 4
        question["QCLASS"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
        CUR_BYTE += 4
        response["question-" + str(j)] = question
        question = {}
 

    #parse answerss
    answer = {}
    for i in range(NUM_ANSWERS):
        answer["name"] = ''
        if data[CUR_BYTE: CUR_BYTE + 2] == "c0":
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
        answer["TYPE"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
        CUR_BYTE += 4
        answer["CLASS"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
        CUR_BYTE += 4
        answer["TTL"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
        CUR_BYTE += 8
        answer["RDLENGTH"] = int(data[CUR_BYTE : CUR_BYTE + 4], 16)
        CUR_BYTE += 4
        answer["RDATA"] = ''
        if answer["TYPE"] == 1: #parse A record response
            for z in range(answer["RDLENGTH"]*2-4):
                answer["RDATA"] += str(int(data[CUR_BYTE : CUR_BYTE+2], 16))
                CUR_BYTE += 2
                if z != answer["RDLENGTH"]*2-5: 
                    answer["RDATA"] += '.'
                    
            response["answer-" + str(i)] = answer
            answer = {}
        elif answer["TYPE"] == 2: #parse NS records
            ns_rdata = {}

            ns_rdata["NSDNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)

            answer["RDATA"] = ns_rdata
            response["answer-" + str(i)] = answer
            answer = {}
        elif answer["TYPE"] == 5:   #parse CNAME records
            cname_rdata = {}

            cname_rdata["CNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)

            answer["RDATA"] = cname_rdata
            response["answer-" + str(i)] = answer
            answer = {}
        elif answer["TYPE"] == 6: #parse SOA records
            soa_rdata = {}
            print('a', CUR_BYTE)
            soa_rdata["MNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)
            print('a', CUR_BYTE)
            soa_rdata["RNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)
            print('a', CUR_BYTE)
            soa_rdata["SERIAL"] = data[CUR_BYTE : CUR_BYTE + 8]
            CUR_BYTE += 8
            soa_rdata["REFRESH"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
            CUR_BYTE += 8
            soa_rdata["RETRY"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
            CUR_BYTE += 8
            soa_rdata["EXPIRE"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
            CUR_BYTE += 8
            soa_rdata["MINIMUM"] = int(data[CUR_BYTE : CUR_BYTE + 8], 16)
            CUR_BYTE += 8

            answer["RDATA"] = soa_rdata
            response["answer-" + str(i)] = answer
            answer = {}
        elif answer["TYPE"] == 12: #parse PTR records
            ptr_rdata = {}

            ptrd_rdata["PTRDNAME"], CUR_BYTE = parse_domain(CUR_BYTE, data)

            answer["RDATA"] = ptr_rdata
            response["answer-" + str(i)] = answer
            answer = {}
        elif answer["TYPE"] == 15:  #parse MX record response
            answer["PREFRENCE"] = int(data[CUR_BYTE : CUR_BYTE+4], 16)
            CUR_BYTE += 4
            LEN_SECTION = int(data[CUR_BYTE : CUR_BYTE+2], 16)
            CUR_BYTE += 2
            while LEN_SECTION != 0:
                try:
                    for a in range(LEN_SECTION):
                        answer["RDATA"] += bytes.fromhex(data[CUR_BYTE : CUR_BYTE+2]).decode('ascii')
                        CUR_BYTE += 2
                    LEN_SECTION = int(data[CUR_BYTE : CUR_BYTE+2], 16)
                    CUR_BYTE += 2
                    answer["RDATA"] += '.'
                    if LEN_SECTION == 0:
                        break
                    elif LEN_SECTION == 192: #192=c0 means pointer to earlier text encoding
                        CUR_BYTE = int(data[CUR_BYTE : CUR_BYTE+2], 16) * 2
                        LEN_SECTION = int(data[CUR_BYTE : CUR_BYTE+2], 16)
                        CUR_BYTE += 2
                except Exception as e:
                    print("ERROR : ", e)
            response["answer-" + str(i)] = answer
            answer = {}
        elif answer["TYPE"] == 16: #parse TXT records -- truncation issue
            string_length = int(data[CUR_BYTE : CUR_BYTE + 2], 16)
            CUR_BYTE += 2
            for a in range(string_length):
                answer["RDATA"] += bytes.fromhex(data[CUR_BYTE : CUR_BYTE + 2]).decode("ascii")
                CUR_BYTE += 2
            response["answer-" + str(i)] = answer
            answer = {}
        
 
    pp = pprint.PrettyPrinter(indent=4)
    pprint.pprint(response)

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

if __name__ == "__main__":
    
    qname = 'CNAME'    
    ip = "8.8.8.8"
    
    #domain = "saep.io"
    #domain = "twitch.tv"
    domain = "test.quantreads.com"
    
    port = 53
    udp_dns(ip, port, domain, qname)