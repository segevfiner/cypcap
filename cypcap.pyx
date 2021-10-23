# cython: language_level=3str

import socket
import enum
cimport cpcap


IF UNAME_SYSNAME == "Windows":
    include "npcap.pxi"


class error(Exception):
    def __init__(self, int code, str msg):
        self.code = code
        self.msg = msg


cdef char init_errbuf[cpcap.PCAP_ERRBUF_SIZE]
if cpcap.pcap_init(cpcap.PCAP_CHAR_ENC_UTF_8, init_errbuf) < 0:
    raise error(-1, init_errbuf)


class PcapIf:
    def __init__(self, name, description, addresses, flags):
        self.name = name
        self.description = description
        self.addresses = addresses
        self.flags = flags

    def __repr__(self):
        return f"<PcapIf(name={self.name!r}, description={self.description!r})>"


cdef object PcapIf_from_c(cpcap.pcap_if_t* dev):
    cdef cpcap.pcap_addr* addr

    addresses = []
    addr = dev.addresses
    while addr:
        addresses.append(PcapAddr_from_c(addr))
        addr = addr.next

    return PcapIf(
        dev.name.decode(),
        dev.description.decode(),
        addresses,
        PcapIfFlags(dev.flags),
    )


class PcapIfFlags(enum.IntFlag):
    LOOPBACK = cpcap.PCAP_IF_LOOPBACK
    UP = cpcap.PCAP_IF_UP
    RUNNING = cpcap.PCAP_IF_RUNNING
    WIRELESS = cpcap.PCAP_IF_WIRELESS
    CONNECTION_STATUS = cpcap.PCAP_IF_CONNECTION_STATUS
    CONNECTION_STATUS_UNKNOWN = cpcap.PCAP_IF_CONNECTION_STATUS_UNKNOWN
    CONNECTION_STATUS_CONNECTED = cpcap.PCAP_IF_CONNECTION_STATUS_CONNECTED
    CONNECTION_STATUS_DISCONNECTED = cpcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED
    CONNECTION_STATUS_NOT_APPLICABLE = cpcap.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE


class PcapAddr:
    def __init__(self, addr, netmask, broadaddr, dstaddr):
        self.addr = addr
        self.netmask = netmask
        self.broadaddr = broadaddr
        self.dstaddr = dstaddr


cdef object PcapAddr_from_c(cpcap.pcap_addr* addr):
    return PcapAddr(
        makesockaddr_addr(addr.addr),
        makesockaddr_addr(addr.netmask),
        makesockaddr_addr(addr.broadaddr),
        makesockaddr_addr(addr.dstaddr),
    )


cdef object makesockaddr_addr(cpcap.sockaddr* addr):
    if not addr:
        return None
    elif addr.sa_family == cpcap.AF_INET:
        # TODO Barf... Anything less digusting?
        return socket.inet_ntop(socket.AF_INET, (<unsigned char*>(&(<cpcap.sockaddr_in*>addr).sin_addr.s_addr))[:4])
    else:
        return (<unsigned char*>addr)[:sizeof(cpcap.sockaddr)]


def findalldevs():
    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_if_t* devs
    cdef cpcap.pcap_if_t* dev

    if cpcap.pcap_findalldevs(&devs, errbuf) < 0:
        raise error(-1, errbuf)

    try:
        result = []
        dev = devs
        while dev:
            result.append(PcapIf_from_c(dev))
            dev = dev.next

        return result
    finally:
        cpcap.pcap_freealldevs(devs)

def lib_version():
    """Get the version information for libpcap."""
    return cpcap.pcap_lib_version().decode()
