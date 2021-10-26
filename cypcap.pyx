# cython: language_level=3str

import socket  # To make sure WinSock2 is initialized
import enum
import warnings
cimport cython
from cpython cimport PyObject, PyErr_SetFromErrno
cimport cpcap
cimport csocket


include "npcap.pxi"


class DatalinkType(enum.IntEnum):
    NULL_ = cpcap.DLT_NULL
    EN10MB = cpcap.DLT_EN10MB
    EN3MB = cpcap.DLT_EN3MB
    AX25 = cpcap.DLT_AX25
    PRONET = cpcap.DLT_PRONET
    CHAOS = cpcap.DLT_CHAOS
    IEEE802 = cpcap.DLT_IEEE802
    ARCNET = cpcap.DLT_ARCNET
    SLIP = cpcap.DLT_SLIP
    PPP = cpcap.DLT_PPP
    FDDI = cpcap.DLT_FDDI

    @property
    def description(self):
        return cpcap.pcap_datalink_val_to_description_or_dlt(self).decode()


class error(Exception):
    def __init__(self, code, msg):
        self.code = ErrorCode(code)
        self.msg = msg
        super().__init__(self.code, self.msg)


class warning(Warning):
    pass


cdef char init_errbuf[cpcap.PCAP_ERRBUF_SIZE]
if cpcap.pcap_init(cpcap.PCAP_CHAR_ENC_UTF_8, init_errbuf) < 0:
    raise error(ErrorCode.ERROR, init_errbuf.decode())


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
        dev.description.decode() if dev.description is not NULL else None,
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

    @property
    def description(self):
        return cpcap.pcap_statustostr(self).decode()


class WarningCode(enum.IntEnum):
    WARNING = cpcap.PCAP_WARNING
    PROMISC_NOTSUP = cpcap.PCAP_WARNING_PROMISC_NOTSUP
    TSTAMP_TYPE_NOTSUP = cpcap.PCAP_WARNING_TSTAMP_TYPE_NOTSUP


class Direction(enum.IntEnum):
    INOUT = cpcap.PCAP_D_INOUT
    IN = cpcap.PCAP_D_IN
    OUT = cpcap.PCAP_D_OUT


NETMASK_UNKNOWN = cpcap.PCAP_NETMASK_UNKNOWN


class TstampType(enum.IntEnum):
    HOST = cpcap.PCAP_TSTAMP_HOST
    HOST_LOWPREC = cpcap.PCAP_TSTAMP_HOST_LOWPREC
    HOST_HIPREC = cpcap.PCAP_TSTAMP_HOST_HIPREC
    ADAPTER = cpcap.PCAP_TSTAMP_ADAPTER
    ADAPTER_UNSYNCED = cpcap.PCAP_TSTAMP_ADAPTER_UNSYNCED
    HOST_HIPREC_UNSYNCED = cpcap.PCAP_TSTAMP_HOST_HIPREC_UNSYNCED

    @property
    def name(self):
        return cpcap.pcap_tstamp_type_val_to_name(self).decode()

    @property
    def description(self):
        return cpcap.pcap_tstamp_type_val_to_description(self).decode()


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


@cython.freelist(8)
cdef class Pkthdr:
    cdef cpcap.pcap_pkthdr pkthdr

    @staticmethod
    cdef from_ptr(const cpcap.pcap_pkthdr* pkthdr):
        cdef Pkthdr self = Pkthdr.__new__(Pkthdr)
        self.pkthdr = pkthdr[0]
        return self

    def __repr__(self):
        return f"<Pkthdr(ts={self.ts!r}, caplen={self.caplen!r}, len={self.len!r})>"

    @property
    def ts(self):
        return self.pkthdr.ts.tv_sec + self.pkthdr.ts.tv_usec / 1000000

    # TODO Consider a ts_datetime property that returns ts as a datetime (What about the timezone though...)

    @property
    def caplen(self):
        return self.pkthdr.caplen

    @property
    def len(self):
        return self.pkthdr.len


@cython.freelist(8)
cdef class Stat:
    cdef cpcap.pcap_stat stat

    def __repr__(self):
        return f"<Stat recv={self.recv!r} drop={self.drop!r} ifdrop={self.ifdrop!r}>"

    @property
    def recv(self):
        return self.stat.ps_recv

    @property
    def drop(self):
        return self.stat.ps_drop

    @property
    def ifdrop(self):
        return self.stat.ps_ifdrop


def findalldevs():
    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_if_t* dev

    cdef cpcap.pcap_if_t* devs
    err = cpcap.pcap_findalldevs(&devs, errbuf)
    if err < 0:
        raise error(err, errbuf.decode())

    try:
        result = []
        dev = devs
        while dev:
            result.append(PcapIf_from_c(dev))
            dev = dev.next

        return result
    finally:
        cpcap.pcap_freealldevs(devs)


def lookupnet(device):
    if isinstance(device, PcapIf):
        device = device.name

    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.bpf_u_int32 net
    cdef cpcap.bpf_u_int32 mask
    err = cpcap.pcap_lookupnet(device, &net, &mask, errbuf)
    if err < 0:
        raise error(err, errbuf.decode())

    return net, mask


def create(source):
    if isinstance(source, PcapIf):
        source = source.name

    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_create(source.encode(), errbuf)
    if not pcap:
        raise error(ErrorCode.ERROR, errbuf.decode())

    return Pcap.from_ptr(pcap)


def open_live(device, snaplen, promisc, to_ms):
    if isinstance(device, PcapIf):
        device = device.name

    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_open_live(device.encode(), snaplen, promisc, to_ms, errbuf)
    if not pcap:
        raise error(ErrorCode.ERROR, errbuf.decode())

    return Pcap.from_ptr(pcap)


cpdef open_dead(linktype, snaplen, precision=TstampPrecision.MICRO):
   cdef cpcap.pcap_t* pcap = cpcap.pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision)
   return Pcap.from_ptr(pcap)


def open_offline(fname, precision=TstampPrecision.MICRO):
    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_open_offline_with_tstamp_precision(fname, precision, errbuf)
    if not pcap:
        raise error(ErrorCode.ERROR, errbuf.decode())

    return Pcap.from_ptr(pcap)


def compile(linktype, snaplen, filter_, optimize, netmask):
    with open_dead(linktype, snaplen) as pcap:
        return pcap.compile(filter_, optimize, netmask)


cdef struct _LoopCallbackContext:
    PyObject* pcap
    PyObject* func


# TODO Is the way we propogate exceptions here safe?
cdef void _loop_callback(unsigned char* user, const cpcap.pcap_pkthdr* pkt_header, const unsigned char* pkt_data) except * with gil:
    try:
        ctx = <_LoopCallbackContext*>user
        (<object>ctx.func)(Pkthdr.from_ptr(pkt_header), pkt_data[:pkt_header.caplen])
    except:
        cpcap.pcap_breakloop((<Pcap>ctx.pcap).pcap)
        raise


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
        if self.pcap is NULL:
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

    def loop(self, int cnt, callback):
        self._check_closed()

        cdef _LoopCallbackContext ctx
        ctx.pcap = <PyObject*>self
        ctx.func = <PyObject*>callback

        with nogil:
            err = cpcap.pcap_loop(self.pcap, cnt, _loop_callback, <unsigned char*>&ctx)
        if err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode)

    def dispatch(self, int cnt, callback):
        self._check_closed()

        cdef _LoopCallbackContext ctx
        ctx.pcap = <PyObject*>self
        ctx.func = <PyObject*>callback

        with nogil:
            err = cpcap.pcap_dispatch(self.pcap, cnt, _loop_callback, <unsigned char*>&ctx)
        if err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode())

    def breakloop(self):
        self._check_closed()

        cpcap.pcap_breakloop(self.pcap)

    def getnonblock(self):
        self._check_closed()

        cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
        result = cpcap.pcap_getnonblock(self.pcap, errbuf)
        if result < 0:
            raise error(result, errbuf.decode())

        return bool(result)

    def setnonblock(self, nonblock):
        self._check_closed()

        cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
        result = cpcap.pcap_setnonblock(self.pcap, nonblock, errbuf)
        if result < 0:
            raise error(result, errbuf.decode())

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

    def list_tstamp_types(self):
        self._check_closed()

        cdef int* tstamp_types
        cdef int num = cpcap.pcap_list_tstamp_types(self.pcap, &tstamp_types)
        if num < 0:
            raise error(num, cpcap.pcap_geterr(self.pcap).decode())

        try:
            result = []
            for tstamp_type in tstamp_types[:num]:
                result.append(TstampType(tstamp_type))

            return result
        finally:
            cpcap.pcap_free_tstamp_types(tstamp_types)

    def datalink(self):
        self._check_closed()

        result = cpcap.pcap_datalink(self.pcap)
        if result < 0:
            raise error(result, cpcap.pcap_statustostr(result).decode())

        try:
            return DatalinkType(result)
        except ValueError:
            return result

    def list_datalinks(self):
        self._check_closed()

        cdef int* datalinks
        cdef int num = cpcap.pcap_list_datalinks(self.pcap, &datalinks)
        if num < 0:
            raise error(num, cpcap.pcap_statustostr(num).decode())

        try:
            result = []
            for datalink in datalinks[:num]:
                try:
                    result.append(DatalinkType(datalink))
                except ValueError:
                    result.append(datalink)

            return result
        finally:
            cpcap.pcap_free_datalinks(datalinks)

    def set_datalink(self, datalink):
        self._check_closed()

        result = cpcap.pcap_set_datalink(self.pcap, datalink)
        if result < 0:
            raise error(result, cpcap.pcap_geterr(self.pcap).decode())

        return result

    def snapshot(self):
        self._check_closed()

        result = cpcap.pcap_snapshot(self.pcap)
        if result < 0:
            raise error(result, cpcap.pcap_statustostr(result).decode())

        return result

    def is_swapped(self):
        self._check_closed()

        result = cpcap.pcap_is_swapped(self.pcap)
        if result < 0:
            raise error(result, cpcap.pcap_statustostr(result).decode())

        return result

    def compile(self, filter_, optimize, netmask):
        self._check_closed()

        cdef BpfProgram bpf_prog = BpfProgram.__new__(BpfProgram)
        err = cpcap.pcap_compile(self.pcap, &bpf_prog.bpf_prog, filter_.encode(), optimize, netmask)
        if err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode())

        return bpf_prog

    def setfilter(self, BpfProgram bpf_prog):
        self._check_closed()

        err = cpcap.pcap_setfilter(self.pcap, &bpf_prog.bpf_prog)
        if err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode())

    def setdirection(self, d):
        self._check_closed()

        err = cpcap.pcap_setdirection(self.pcap, d)
        if err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode())

    def stats(self):
        self._check_closed()

        cdef Stat stat = Stat.__new__(Stat)
        err = cpcap.pcap_stats(self.pcap, &stat.stat)
        if err < 0:
            raise error(err, cpcap.pcap_geterr(self.pcap).decode())

        return stat

    def dump_open(self, fname):
        self._check_closed()

        cdef Dumper dumper = Dumper.__new__(Dumper)
        dumper.dumper = cpcap.pcap_dump_open(self.pcap, fname)
        if not dumper.dumper:
            raise error(ErrorCode.ERROR, cpcap.pcap_geterr(self.pcap).decode())

        return dumper

    def dump_open_append(self, fname):
        self._check_closed()

        cdef Dumper dumper = Dumper.__new__(Dumper)
        dumper.dumper = cpcap.pcap_dump_open_append(self.pcap, fname)
        if not dumper.dumper:
            raise error(ErrorCode.ERROR, cpcap.pcap_geterr(self.pcap).decode())

        return dumper

    def inject(self, buf):
        self._check_closed()

        result = cpcap.pcap_inject(self.pcap, <unsigned char*>buf, <int>len(buf))
        if result < 0:
            raise error(ErrorCode.ERROR, cpcap.pcap_geterr(self.pcap).decode())

        return result

    def sendpacket(self, buf):
        self._check_closed()

        result = cpcap.pcap_sendpacket(self.pcap, <unsigned char*>buf, <int>len(buf))
        if result < 0:
            raise error(ErrorCode.ERROR, cpcap.pcap_geterr(self.pcap).decode())


# TODO Support dumping/loading bytecode, __getitem__?
cdef class BpfProgram:
    cdef cpcap.bpf_program bpf_prog

    def __dealloc__(self):
        if self.bpf_prog.bf_insns:
            cpcap.pcap_freecode(&self.bpf_prog)

    def offline_filter(self, Pkthdr pkt_header, pkt_data):
        return cpcap.pcap_offline_filter(&self.bpf_prog, &pkt_header.pkthdr, pkt_data)

    def dump(self, option=0):
        cpcap.bpf_dump(&self.bpf_prog, option)


cdef class Dumper:
    cdef cpcap.pcap_dumper_t* dumper

    def __dealloc__(self):
        # TODO ResourceWarning?
        self.close()

    cpdef close(self):
        if self.dumper:
            cpcap.pcap_dump_close(self.dumper)
            self.dumper = NULL

    cdef int _check_closed(self) except -1:
        if self.dumper is NULL:
            raise ValueError("Operation on closed Dumper")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.close()

    def dump(self, Pkthdr pkt_header, pkt_data):
        self._check_closed()

        cpcap.pcap_dump(<unsigned char*>self.dumper, &pkt_header.pkthdr, pkt_data)

    def ftell(self):
        self._check_closed()

        result = cpcap.pcap_dump_ftell64(self.dumper)
        if result == cpcap.PCAP_ERROR:
            raise error(result, cpcap.pcap_statustostr(<int>result).decode())

        return result


def lib_version():
    """Get the version information for libpcap."""
    return cpcap.pcap_lib_version().decode()
