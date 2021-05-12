import socket
import struct, binascii
import sys

def udp_dns(ip, port, query):
    header = b'fedc01000001000000000000'


    #QUESTION:
    question = b''
    split = query.split('.')
    for part in split:
        part_bits = part.encode('ascii')
        length = f'{len(part_bits):02}'.encode('ascii') #get length of bytes, pad it to 2 bytes and encode
        question += length
        question += binascii.hexlify(part_bits)


    header += question
    null = b'00' #null terminator at the end of the QNAME section
    header += null

    qtype = b'0005' # (5) for CNAME records
    #qtype = b'000f' # (15) for MX records
    #qtype = b'0001' #QTYPE:  (1) for A records
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
    data = sock.recv(1024)
    while(1):
        if data is not None:
            if len(data) > 0:
                break
    sock.close()
    #return format_hex(binascii.hexlify(qfull).decode("utf-8"))
    return format_hex(binascii.hexlify(data).decode("utf-8"))

    
def format_hex(hex):
    """format_hex returns a pretty version of a hex string"""
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    pairs = [" ".join(octets[i:i+2]) for i in range(0, len(octets), 2)]
    return "\n".join(pairs)



if __name__ == "__main__":
    ip = "8.8.8.8"
    query = "saep.io"
    port = 53
    print(udp_dns(ip, port, query))


###   A Type DNS Lookup Request
# fe dc  -- 8 byte identifier                                                               }
# 01 00  -- query flags  QR = 0 / OPCODE = 0 / TC = 0 / RD = 1 / QDCOUNT = 1                }
# 00 01  -- # of question                                                                   }
# 00 00  -- # of answers                                                                    }  HEADER SECTION
# 00 00  -- # of authroity records                                                          }
# 00 00  -- # of additional records                                                         }
# 04 73  -- '04' = next 4 bytes is the first section of QNAME // '73' = 's'    }
# 61 65  -- '61' = a // '65' = e                                               }     
# 70 02  -- '70' = p // '02' next two bytes is the second section of QNAME     }
# 69 6f  -- '69' = i // '6f' = o                                               }    QUESTION SECTION
# 00     -- '00' = null byte at end of QNAME  //                               }
# 00 01  -- DNS record type  :  1 = A type                                     }
# 00 01  -- Class of the lookup  :  1 = Internet                               }

###   A Type DNS Lookup Response
# fe dc  -- same identifier as above                                                            }
# 81 80  -- query flags  QR = 1 / OPCODE = 0 / AA = 0 / TC = 0 / RD = 1 / RA = 1 / RCODE = 0    }
# 00 01  -- # of questions has not changed                                                      } HEADER
# 00 04  -- # of answers is now 4                                                               } (changed)
# 00 00  -- no authority records                                                                }
# 00 00  -- no aditional records                                                                }
# 04 73  -- QUESTION SECTION IS THE SAME AS ABOVE   }
# 61 65  -- QUESTION SECTION IS THE SAME AS ABOVE   }
# 70 02  -- QUESTION SECTION IS THE SAME AS ABOVE   }
# 69 6f  -- QUESTION SECTION IS THE SAME AS ABOVE   }QUESTION
# 00 00  -- QUESTION SECTION IS THE SAME AS ABOVE   }(same)
# 01 00  -- QUESTION SECTION IS THE SAME AS ABOVE   }
# 01     -- QUESTION SECTION IS THE SAME AS ABOVE   }
# c0 0c  -- name offset = 12 (from begining)                    }
# 00 01  -- DNS record type  :  1 = A                           }
# 00 01  -- Class of loopup  :  1 = internet                    }
# 00 00  -- NULL BYTES??                                        } ANSWER 1
# 00 3b  -- Time To Live                                        }
# 00 04  -- RDLENGTH = 4 (length of following RDDATA section)   }
# 8f cc  -- '8f' = 143 / 'cc' = 204                             }
# 27 3a  -- '27' = 39 / '3a' = 58  : IP = 143.204.39.58         }
# c0 0c  -- name offset                                             ]
# 00 01  -- DNS record type                                         ]
# 00 01  -- Class of lookup                                         ]
# 00 00  -- NULL?                                                   ]
# 00 3b  -- time to live                                            ] ANSWER 2
# 00 04  -- RDLENGTH = 4                                            ]
# 8f cc                                                             ]
# 27 1c  -- IP = 143.204.39.28                                      ]
# c0 0c  -- name offset                                         }
# 00 01  -- DNS record type                                     }
# 00 01  -- class                                               }
# 00 00  -- null                                                }
# 00 3b  -- time to live                                        } ANSWER 3
# 00 04  -- RDLENGTH                                            }
# 8f cc                                                         }
# 27 60  -- IP = 143.204.39.96                                  }
# c0 0c  -- name offset                                             ]
# 00 01  -- DNS record Type                                         ]
# 00 01  -- class                                                   ]
# 00 00  -- null                                                    ]
# 00 3b  -- TTL                                                     ] ANSWER 4
# 00 04  -- RDLENGTH                                                ]
# 8f cc                                                             ]
# 27 7b  -- IP = 143.204.39.123                                     ]

#--------------------------------------------------------------------------------------------------------------------
###  MX DNS Lookup Request
# fe dc  -- Identifier
# 01 00  -- Flags  :  QR = 0 / OPCODE = 0 / TC = 0 / RD = 1 / QDCOUNT = 1
# 00 01  -- # question = 1
# 00 00  -- # answer
# 00 00  -- # authorities
# 00 00  -- # additional records
# 04 73
# 61 65
# 70 02
# 69 6f
# 00     -- encoded "saep.io"
# 00 0f  -- record type = MX (15)
# 00 01  -- class = Internet (1)

### MX DNS Response
# fe dc  -- ident
# 81 80  -- flags : QR = 1 / OPCODE = 0 / AA = 0 / TC = 0 / RD = 1 / RA = 1 / RCODE = 0
# 00 01  -- 1 question
# 00 01  -- 1 answer
# 00 00  -- 0 authorities
# 00 00  -- 0 additional records
# 04 73
# 61 65
# 70 02
# 69 6f
# 00     -- encoded "saep.io"
# 00 0f  -- record type (MX)
# 00 01  -- class (IN)
# c0 0c  -- name offset (12)
# 00 0f  -- record type (MX)
# 00 01  -- class (IN)
# 00 00  -- null
# 0e 0f  -- TTL
# 00 1f  -- RDLENGTH (31)
# 00 00  -- null?
# 07 73  -- next 7 bytes is first part // '73' = a
# 61 65  -- '61' = a // '65' = e
# 70 2d  -- '70' = p  // '2d' = -
# 69 6f  -- '69' = i  // '6f' = o
# 04 6d  -- next 4 bytes is second part  // '6d' = m
# 61 69  -- '61' = a // '69' = i
# 6c 02  -- '6c' = l  // next 2 bytes is third part
# 65 6f  -- '65' = e // '6f' = o
# 07 6f  -- next 7 bytes is fourth part  //  '6f' = o
# 75 74  -- '75' = u // '74' = t
# 6c 6f  -- '6c' = l // '6f' = o
# 6f 6b  -- '6f' = o // '6b' = k
# 03 63  -- next 3 bytes is fifth part  //  '63' = c
# 6f 6d  -- '6f' = o // '6d' = m
# 00     -- null               ----- saep-io.mail.eo.outlook.com

#---------------------------------------------------------------------------------------------------------------------