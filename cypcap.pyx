# cython: language_level=3str

cimport cpcap


IF UNAME_SYSNAME == "Windows":
    include "npcap.pxi"


class error(Exception):
    def __init__(self, int code, str msg):
        self.code = code
        self.msg = msg


cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
if cpcap.pcap_init(cpcap.PCAP_CHAR_ENC_UTF_8, errbuf) < 0:
    raise error(-1, errbuf)


def lib_version():
    return cpcap.pcap_lib_version().decode()
