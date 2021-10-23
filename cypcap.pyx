# cython: language_level=3str

import socket
import enum
import warnings
cimport cython
from cpython cimport PyErr_SetFromErrno
cimport cpcap
cimport csocket


IF UNAME_SYSNAME == "Windows":
    include "npcap.pxi"


class error(Exception):
    def __init__(self, int code, str msg):
        self.code = code
        self.msg = msg


class warning(Warning):
    pass


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

    def __repr__(self):
        return f"PcapAddr({self.addr!r}, {self.netmask!r}, {self.broadaddr!r}, {self.dstaddr!r})"


cdef object PcapAddr_from_c(cpcap.pcap_addr* addr):
    return PcapAddr(
        makesockaddr_addr(addr.addr),
        makesockaddr_addr(addr.netmask),
        makesockaddr_addr(addr.broadaddr),
        makesockaddr_addr(addr.dstaddr),
    )


cdef makesockaddr_addr(csocket.sockaddr* addr):
    cdef char inet_buf[csocket.INET_ADDRSTRLEN]
    cdef char inet6_buf[csocket.INET6_ADDRSTRLEN]

    if not addr:
        return None
    elif addr.sa_family == csocket.AF_INET:
        if not csocket.inet_ntop(csocket.AF_INET, &(<csocket.sockaddr_in*>addr).sin_addr, inet_buf, sizeof(inet_buf)):
            PyErr_SetFromErrno(OSError)
        return inet_buf.decode()
    elif addr.sa_family == csocket.AF_INET6:
        if not csocket.inet_ntop(csocket.AF_INET6, &(<csocket.sockaddr_in6*>addr).sin6_addr, inet6_buf, sizeof(inet6_buf)):
            PyErr_SetFromErrno(OSError)
        return inet6_buf.decode()
    else:
        # TODO What should we do for unknown sa_family?
        return (<unsigned char*>addr)[:sizeof(csocket.sockaddr)]


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


@cython.freelist(8)
@cython.internal
cdef class Pkthdr:
    cdef cpcap.pcap_pkthdr pkthdr

    @staticmethod
    cdef from_ptr(cpcap.pcap_pkthdr* pkthdr):
        cdef Pkthdr self = Pkthdr.__new__(Pkthdr)
        self.pkthdr = pkthdr[0]
        return self

    def __repr__(self):
        return f"<Pkthdr(ts={self.ts!r}, caplen={self.caplen!r}, len={self.len!r})>"

    @property
    def ts(self):
        return self.pkthdr.ts.tv_sec + self.pkthdr.ts.tv_usec / 1000000

    @property
    def caplen(self):
        return self.pkthdr.caplen

    @property
    def len(self):
        return self.pkthdr.len


def create(source):
    if isinstance(source, PcapIf):
        source = source.name

    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_create(source.encode(), errbuf)
    if not pcap:
        raise error(-1, errbuf)

    return Pcap.from_ptr(pcap)


@cython.internal
cdef class Pcap:
    cdef cpcap.pcap_t* pcap

    @staticmethod
    cdef from_ptr(cpcap.pcap_t* pcap):
        cdef Pcap self = Pcap.__new__(Pcap)
        self.pcap = pcap
        return self

    def __dealloc__(self):
        if self.pcap:
            cpcap.pcap_close(self.pcap)

    def __iter__(self):
        return self

    def __next__(self):
        cdef cpcap.pcap_pkthdr* pkt_header
        cdef const unsigned char* pkt_data

        err = cpcap.pcap_next_ex(self.pcap, &pkt_header, &pkt_data)
        if err == cpcap.PCAP_ERROR_BREAK:
            raise StopIteration
        elif err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode())
        elif err == 0:
            return None, None

        # TODO I wonder if there is a way to use the Python buffer interface to possibly save the copy
        # ownership is a problem since the pointer is only valid until the next call
        return Pkthdr.from_ptr(pkt_header), pkt_data[:pkt_header.caplen]

    def set_snaplen(self, snaplen):
        err = cpcap.pcap_set_snaplen(self.pcap, snaplen)
        if err:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def set_promisc(self, promisc):
        err = cpcap.pcap_set_promisc(self.pcap, promisc)
        if err:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def set_timeout(self, timeout):
        err = cpcap.pcap_set_timeout(self.pcap, timeout)
        if err:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def activate(self):
        err = cpcap.pcap_activate(self.pcap)
        if err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode())
        elif err > 1:
            warnings.warn(cpcap.pcap_geterr(self.pcap).decode(), warning)

    def datalink(self):
        return cpcap.pcap_datalink(self.pcap)


def lib_version():
    """Get the version information for libpcap."""
    return cpcap.pcap_lib_version().decode()
