# cython: language_level=3str

import socket  # To make sure WinSock2 is initialized
import enum
import warnings
cimport cython
from cpython cimport PyErr_SetFromErrno
cimport cpcap
cimport csocket


IF UNAME_SYSNAME == "Windows":
    include "npcap.pxi"


class error(Exception):
    def __init__(self, code, msg):
        self.code = ErrorCode(code)
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


class ErrorCode(enum.IntEnum):
    ERROR = cpcap.PCAP_ERROR
    BREAK = cpcap.PCAP_ERROR_BREAK
    NOT_ACTIVATED = cpcap.PCAP_ERROR_NOT_ACTIVATED
    ACTIVATED = cpcap.PCAP_ERROR_ACTIVATED
    NO_SUCH_DEVICE = cpcap.PCAP_ERROR_NO_SUCH_DEVICE
    RFMON_NOTSUP = cpcap.PCAP_ERROR_RFMON_NOTSUP
    NOT_RFMON = cpcap.PCAP_ERROR_NOT_RFMON
    PERM_DENIED = cpcap.PCAP_ERROR_PERM_DENIED
    IFACE_NOT_UP = cpcap.PCAP_ERROR_IFACE_NOT_UP
    CANTSET_TSTAMP_TYPE = cpcap.PCAP_ERROR_CANTSET_TSTAMP_TYPE
    PROMISC_PERM_DENIED = cpcap.PCAP_ERROR_PROMISC_PERM_DENIED
    TSTAMP_PRECISION_NOTSUP = cpcap.PCAP_ERROR_TSTAMP_PRECISION_NOTSUP


class TstampPrecision(enum.IntEnum):
    MICRO = cpcap.PCAP_TSTAMP_PRECISION_MICRO
    NANO = cpcap.PCAP_TSTAMP_PRECISION_NANO


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

    # TODO Consider a ts_datetime property that returns ts as a datetime

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


def open_live(device, snaplen, promisc, to_ms):
    if isinstance(device, PcapIf):
        device = device.name

    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_open_live(device.encode(), snaplen, promisc, to_ms, errbuf)
    if not pcap:
        raise error(-1, errbuf)

    return Pcap.from_ptr(pcap)


def open_dead(linktype, snaplen, precision=TstampPrecision.MICRO):
   cdef cpcap.pcap_t* pcap = cpcap.pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision)
   return Pcap.from_ptr(pcap)


def open_offline(fname, precision=TstampPrecision.MICRO):
    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_open_offline_with_tstamp_precision(fname, precision, errbuf)
    if not pcap:
        raise error(-1, errbuf)

    return Pcap.from_ptr(pcap)


cdef class Pcap:
    cdef cpcap.pcap_t* pcap

    @staticmethod
    cdef from_ptr(cpcap.pcap_t* pcap):
        cdef Pcap self = Pcap.__new__(Pcap)
        self.pcap = pcap
        return self

    def __dealloc__(self):
        # TODO ResourceWarning?
        self.close()

    cpdef close(self):
        if self.pcap:
            cpcap.pcap_close(self.pcap)
            self.pcap = NULL

    cdef int _check_closed(self) except -1:
        if self.pcap == NULL:
            raise ValueError("Operation on closed Pcap")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.close()

    def __iter__(self):
        return self

    def __next__(self):
        self._check_closed()

        cdef cpcap.pcap_pkthdr* pkt_header
        cdef const unsigned char* pkt_data

        with nogil:
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
        self._check_closed()

        err = cpcap.pcap_set_snaplen(self.pcap, snaplen)
        if err < 0:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def set_promisc(self, promisc):
        self._check_closed()

        err = cpcap.pcap_set_promisc(self.pcap, promisc)
        if err < 0:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def can_set_rfmon(self):
        self._check_closed()

        result = cpcap.pcap_can_set_rfmon(self.pcap)
        if result < 0:
            raise error(result, cpcap.pcap_statustostr(result).decode())

        return bool(result)

    def set_rfmon(self, rfmon):
        self._check_closed()

        err = cpcap.pcap_set_rfmon(self.pcap, rfmon)
        if err < 0:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def set_timeout(self, timeout):
        self._check_closed()

        err = cpcap.pcap_set_timeout(self.pcap, timeout)
        if err < 0:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def set_tstamp_type(self, tstamp_type):
        self._check_closed()

        # TODO enum
        err = cpcap.pcap_set_tstamp_type(self.pcap, tstamp_type)
        if err < 0:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def set_immediate_mode(self, immediate_mode):
        self._check_closed()

        err = cpcap.pcap_set_immediate_mode(self.pcap, immediate_mode)
        if err < 0:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def set_buffer_size(self, buffer_size):
        self._check_closed()

        err = cpcap.pcap_set_buffer_size(self.pcap, buffer_size)
        if err < 0:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def set_tstamp_precision(self, tstamp_precision):
        self._check_closed()

        # TODO enum
        err = cpcap.pcap_set_tstamp_precision(self.pcap, tstamp_precision)
        if err < 0:
            raise error(err, cpcap.pcap_statustostr(err).decode())

    def get_tstamp_precision(self):
        self._check_closed()

        # TODO enum
        return cpcap.pcap_get_tstamp_precision(self.pcap)

    def activate(self):
        self._check_closed()

        err = cpcap.pcap_activate(self.pcap)
        if err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode())
        elif err > 1:
            # TODO Do we want the warning to include the warning code?
            warnings.warn(cpcap.pcap_geterr(self.pcap).decode(), warning)

    def datalink(self):
        self._check_closed()
        # TODO enum
        return cpcap.pcap_datalink(self.pcap)


def lib_version():
    """Get the version information for libpcap."""
    return cpcap.pcap_lib_version().decode()
