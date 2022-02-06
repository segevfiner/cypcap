# cython: language_level=3str, binding=True
"""
This module is a Cython based binding for modern libpcap.
"""

import sys
import os
import socket  # To make sure WinSock2 is initialized
import enum
import warnings
import threading
from datetime import datetime, timezone
from typing import Optional, Union, List, Tuple, Callable

cimport cython
from libc cimport stdio
from libc.stdlib cimport malloc, free
from libc.stdint cimport uintptr_t
from cpython cimport PyObject, PyErr_SetFromErrno

from . cimport cpcap
from . cimport csocket


include "npcap.pxi"


# TODO This is a really big enumeration, add more values as requested
class DatalinkType(enum.IntEnum):
    """Datalink types."""
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

    RAW = cpcap.DLT_RAW

    IEEE802_11_RADIO = cpcap.DLT_IEEE802_11_RADIO

    DOCSIS = cpcap.DLT_DOCSIS

    @property
    def description(self) -> str:
        return cpcap.pcap_datalink_val_to_description_or_dlt(self).decode()


class Error(Exception):
    """
    Raised when an error occurs in libpcap.

    .. attribute:: code
       :type: ErrorCode

       Error code.

    .. attribute:: msg
       :type: str

       Error message.
    """
    def __init__(self, code, msg):
        self.code = ErrorCode(code)
        self.msg = msg
        super().__init__(self.code, self.msg)


class NotSupportedError(Exception):
    """
    Raised when an unsupported operation is requested.
    """


class Warning(Warning):
    """
    Warning category for libpcap warnings.

    .. attribute:: code
       :type: ErrorCode

       Error code.

    .. attribute:: msg
       :type: str

       Warning message.
    """
    def __init__(self, code, msg):
        self.code = ErrorCode(code)
        self.msg = msg
        super().__init__(self.code, self.msg)


# Initialize libpcap
cdef char init_errbuf[cpcap.PCAP_ERRBUF_SIZE]
if cpcap.pcap_init(cpcap.PCAP_CHAR_ENC_UTF_8, init_errbuf) < 0:
    raise Error(ErrorCode.ERROR, init_errbuf.decode())


class PcapIf:
    """
    A Pcap interface.

    You can either pass this object or its :attr:`name` to functions expecting an interface.

    .. attribute:: name
       :type: str

       Interface name.

    .. attribute:: description
       :type: Optional[str]

       Interface description.

    .. attribute:: addresses
       :type: PcapAddr

       List of interface addresses.

    .. attribute:: flags
       :type: PcapIfFlags

       Interface flags.
    """

    def __init__(self, name: str, description: Optional[str], addresses: 'PcapAddr', flags: 'PcapIfFlags'):
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
    """Pcap interface flags."""
    LOOPBACK = cpcap.PCAP_IF_LOOPBACK
    UP = cpcap.PCAP_IF_UP
    RUNNING = cpcap.PCAP_IF_RUNNING
    WIRELESS = cpcap.PCAP_IF_WIRELESS
    CONNECTION_STATUS_UNKNOWN = cpcap.PCAP_IF_CONNECTION_STATUS_UNKNOWN
    CONNECTION_STATUS_CONNECTED = cpcap.PCAP_IF_CONNECTION_STATUS_CONNECTED
    CONNECTION_STATUS_DISCONNECTED = cpcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED
    CONNECTION_STATUS_NOT_APPLICABLE = cpcap.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE


class ErrorCode(enum.IntEnum):
    """Pcap error codes."""
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

    WARNING = cpcap.PCAP_WARNING
    WARNING_PROMISC_NOTSUP = cpcap.PCAP_WARNING_PROMISC_NOTSUP
    WARNING_TSTAMP_TYPE_NOTSUP = cpcap.PCAP_WARNING_TSTAMP_TYPE_NOTSUP

    @property
    def description(self):
        """Error code description."""
        return cpcap.pcap_statustostr(self).decode()


class Direction(enum.IntEnum):
    """Direction for :meth:`Pcap.setdirection`."""
    INOUT = cpcap.PCAP_D_INOUT
    IN = cpcap.PCAP_D_IN
    OUT = cpcap.PCAP_D_OUT


NETMASK_UNKNOWN = <cpcap.bpf_u_int32>cpcap.PCAP_NETMASK_UNKNOWN


class TstampType(enum.IntEnum):
    """Timestamp types."""
    HOST = cpcap.PCAP_TSTAMP_HOST
    HOST_LOWPREC = cpcap.PCAP_TSTAMP_HOST_LOWPREC
    HOST_HIPREC = cpcap.PCAP_TSTAMP_HOST_HIPREC
    ADAPTER = cpcap.PCAP_TSTAMP_ADAPTER
    ADAPTER_UNSYNCED = cpcap.PCAP_TSTAMP_ADAPTER_UNSYNCED
    HOST_HIPREC_UNSYNCED = cpcap.PCAP_TSTAMP_HOST_HIPREC_UNSYNCED

    @property
    def name(self) -> str:
        return cpcap.pcap_tstamp_type_val_to_name(self).decode()

    @property
    def description(self) -> str:
        return cpcap.pcap_tstamp_type_val_to_description(self).decode()


class TstampPrecision(enum.IntEnum):
    """Timestamp precision."""
    MICRO = cpcap.PCAP_TSTAMP_PRECISION_MICRO
    NANO = cpcap.PCAP_TSTAMP_PRECISION_NANO


cdef extern object makesockaddr_c(csocket.sockaddr*)


cdef makesockaddr(csocket.sockaddr* addr):
    if addr is NULL:
        return None

    try:
        family = socket.AddressFamily(addr.sa_family)
    except ValueError:
        family = addr.sa_family

    return (family, makesockaddr_c(addr))


class PcapAddr:
    """
    Pcap interface address.

    Addresses are in the same format as used by the :mod:`socket` module.

    .. attribute:: addr
       :type: Tuple[socket.AddressFamily, Tuple]

       Address.

    .. attribute:: netmask
       :type: Tuple[socket.AddressFamily, Tuple]

       Netmask for the address.

    .. attribute:: broadaddr
       :type: Optional[Tuple[socket.AddressFamily, Tuple]]

       Broadcast address for that address.

    .. attribute:: dstaddr
       :type: Optional[Tuple[socket.AddressFamily, Tuple]]

       P2P destination address for that address.
    """

    def __init__(self,
        addr: Tuple[socket.AddressFamily, Tuple],
        netmask: Tuple[socket.AddressFamily, Tuple],
        broadaddr: Optional[Tuple[socket.AddressFamily, Tuple]],
        dstaddr: Optional[Tuple[socket.AddressFamily, Tuple]],
    ):
        self.addr = addr
        self.netmask = netmask
        self.broadaddr = broadaddr
        self.dstaddr = dstaddr

    def __repr__(self):
        return f"PcapAddr(addr={self.addr!r}, netmask={self.netmask!r}, broadaddr={self.broadaddr!r}, dstaddr={self.dstaddr!r})"


cdef object PcapAddr_from_c(cpcap.pcap_addr* addr):
    return PcapAddr(
        makesockaddr(addr.addr),
        makesockaddr(addr.netmask),
        makesockaddr(addr.broadaddr),
        makesockaddr(addr.dstaddr),
    )


@cython.freelist(8)
cdef class Pkthdr:
    """
    Pcap packet header.
    """
    cdef cpcap.pcap_pkthdr pkthdr

    def __init__(self, double ts: float=0.0, caplen: int=0, len: int=0):
        self.ts = ts
        self.pkthdr.caplen = caplen
        self.pkthdr.len = len

    @staticmethod
    cdef from_ptr(const cpcap.pcap_pkthdr* pkthdr):
        cdef Pkthdr self = Pkthdr.__new__(Pkthdr)
        self.pkthdr = pkthdr[0]
        return self

    def __repr__(self):
        return f"Pkthdr(ts={self.ts!r}, caplen={self.caplen!r}, len={self.len!r})"

    @property
    def ts(self) -> int:
        """Timestamp."""
        return self.pkthdr.ts.tv_sec + self.pkthdr.ts.tv_usec / 1000000

    @ts.setter
    def ts(self, double ts: float):
        self.pkthdr.ts.tv_sec = <long>ts
        self.pkthdr.ts.tv_usec = <long>(ts * 1000000 % 1000000)

    @property
    def ts_datetime(self) -> datetime:
        """Timestamp as a naive local datetime."""
        return datetime.fromtimestamp(self.ts)

    @ts_datetime.setter
    def ts_datetime(self, ts_datetime: datetime):
        self.ts = ts_datetime.timestamp()

    @property
    def ts_utcdatetime(self) -> datetime:
        """Timestamp as a naive UTC datetime."""
        return datetime.utcfromtimestamp(self.ts)

    @ts_utcdatetime.setter
    def ts_utcdatetime(self, ts_utcdatetime: datetime):
        if ts_utcdatetime.tzinfo is None:
            ts_utcdatetime = ts_utcdatetime.replace(tzinfo=timezone.utc)

        self.ts = ts_utcdatetime.timestamp()

    @property
    def caplen(self) -> int:
        """Length of portion present."""
        return self.pkthdr.caplen

    @caplen.setter
    def caplen(self, caplen: int):
        self.pkthdr.caplen = caplen

    @property
    def len(self) -> int:
        """Length of this packet (off wire)."""
        return self.pkthdr.len

    @len.setter
    def len(self, len: int):
        self.pkthdr.len = len


@cython.freelist(8)
cdef class Stat:
    """Capture statistics."""
    cdef cpcap.pcap_stat stat

    def __repr__(self):
        return f"<Stat recv={self.recv!r} drop={self.drop!r} ifdrop={self.ifdrop!r}>"

    @property
    def recv(self) -> int:
        """Number of packets received."""
        return self.stat.ps_recv

    @property
    def drop(self) -> int:
        """Number of packets dropped."""
        return self.stat.ps_drop

    @property
    def ifdrop(self) -> int:
        """Drops by interface -- only supported on some platforms."""
        return self.stat.ps_ifdrop


def findalldevs() -> List[PcapIf]:
    """Get a list of capture devices."""
    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_if_t* dev

    cdef cpcap.pcap_if_t* devs
    err = cpcap.pcap_findalldevs(&devs, errbuf)
    if err < 0:
        raise Error(err, errbuf.decode())

    try:
        result = []
        dev = devs
        while dev:
            result.append(PcapIf_from_c(dev))
            dev = dev.next

        return result
    finally:
        cpcap.pcap_freealldevs(devs)


def lookupnet(device: Union[str, PcapIf]) -> Tuple[int, int]:
    """
    Find the IPv4 network number and netmask for a device.

    This is mostly used to pass the netmask to :meth:`Pcap.compile`.
    """
    if isinstance(device, PcapIf):
        device = device.name

    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.bpf_u_int32 net
    cdef cpcap.bpf_u_int32 mask
    err = cpcap.pcap_lookupnet(device.encode(), &net, &mask, errbuf)
    if err < 0:
        raise Error(err, errbuf.decode())

    return net, mask


def create(source: Union[str, PcapIf]) -> Pcap:
    """
    Create a live capture.

    Set any additional configuration and call :meth:`Pcap.activate` to activate the capture.
    """
    if isinstance(source, PcapIf):
        source = source.name

    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_create(source.encode(), errbuf)
    if not pcap:
        raise Error(ErrorCode.ERROR, errbuf.decode())

    return Pcap.from_ptr(pcap, PcapType.LIVE, source)


def open_live(device: Union[str, PcapIf], snaplen: int, promisc: bool, double to_ms: float) -> Pcap:
    """
    Open a device for capturing.

    .. deprecated:: libpcap-1.0
       Prefer :func:`create`
    """
    if isinstance(device, PcapIf):
        device = device.name

    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_open_live(device.encode(), snaplen, promisc, int(to_ms * 1000), errbuf)
    if not pcap:
        raise Error(ErrorCode.ERROR, errbuf.decode())

    return Pcap.from_ptr(pcap, PcapType.LIVE, device)


cpdef Pcap open_dead(linktype: DatalinkType, snaplen: int, precision: TstampPrecision=TstampPrecision.MICRO):
    """Open a fake Pcap for compiling filters or opening a capture for output."""
    cdef cpcap.pcap_t* pcap = cpcap.pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision)
    return Pcap.from_ptr(pcap, PcapType.DEAD)


def open_offline(fname: os.PathLike, precision: TstampPrecision=TstampPrecision.MICRO) -> Pcap:
    """Open a saved capture file for reading."""
    cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
    cdef cpcap.pcap_t* pcap = cpcap.pcap_open_offline_with_tstamp_precision(os.fsencode(fname), precision, errbuf)
    if not pcap:
        raise Error(ErrorCode.ERROR, errbuf.decode())

    return Pcap.from_ptr(pcap, PcapType.OFFLINE, os.fsdecode(fname))


def compile(linktype: DatalinkType, snaplen: int, filter_: str, optimize: bool, netmask: int) -> BpfProgram:
    """
    Compile a filter expression.

    Shortcut for compiling a filter without an active Pcap. You might want to use
    :meth:`Pcap.compile` which will save you from passing some parameters.
    """
    with open_dead(linktype, snaplen) as pcap:
        return pcap.compile(filter_, optimize, netmask)


class PcapType(enum.Enum):
    """Pcap types."""
    LIVE = 1
    DEAD = 2
    OFFLINE = 3


cdef struct _LoopCallbackContext:
    PyObject* pcap
    PyObject* func


# TODO Is the way we propogate exceptions here safe?
cdef void _loop_callback(unsigned char* user, const cpcap.pcap_pkthdr* pkt_header, const unsigned char* pkt_data) except * with gil:
    ctx = <_LoopCallbackContext*>user
    try:
        (<object>ctx.func)(Pkthdr.from_ptr(pkt_header), pkt_data[:pkt_header.caplen])
    except:
        cpcap.pcap_breakloop((<Pcap>ctx.pcap).pcap)
        raise


cdef class Pcap:
    """
    A packet capture.

    Created by one of :func:`create`, :func:`open_live`, :func:`open_dead`, or :func:`open_offline`.

    You need to explicitly :meth:`close` this when done or you will get a :exc:`ResourceWarning`.
    (You can use ``with``).

    To read packets, iterate this object. For example::

        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            print(pkthdr, data)

    .. warning:: Iteration will return ``(None, None)`` in case of packet buffer timeouts.

    Or use :meth:`loop` or :meth:`dispatch`.
    """
    cdef cpcap.pcap_t* pcap
    cdef readonly object type
    cdef readonly str source

    def __init__(self):
        raise TypeError(f"cannot create '{self.__class__.__name__}' instances")

    @staticmethod
    cdef from_ptr(cpcap.pcap_t* pcap, typ, str source=None):
        cdef Pcap self = Pcap.__new__(Pcap)
        self.pcap = pcap
        self.type = typ
        self.source = source
        return self

    def __dealloc__(self):
        if self.pcap:
            warnings.warn(f"unclosed Pcap {self!r}", ResourceWarning, source=self)
            self.close()

    def __repr__(self):
        if self.source is not None:
            return f"<Pcap {self.type.name} on {self.source!r}>"
        else:
            return f"<Pcap {self.type.name}>"

    cpdef close(self):
        """Close the Pcap."""
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
            raise Error(err, cpcap.pcap_geterr(self.pcap).decode())
        elif err == 0:
            return None, None

        # TODO I wonder if there is a way to use the Python buffer interface to possibly save the copy
        # ownership is a problem since the pointer is only valid until the next call
        return Pkthdr.from_ptr(pkt_header), pkt_data[:pkt_header.caplen]

    def loop(self, int cnt, callback: Callable[[Pkthdr, bytes], None]) -> None:
        """
        Process packets from a live capture or savefile.

        Unlike :meth:`dispatch` this does not return on live packet buffer timeouts.
        """
        self._check_closed()

        cdef _LoopCallbackContext ctx
        ctx.pcap = <PyObject*>self
        ctx.func = <PyObject*>callback

        with nogil:
            err = cpcap.pcap_loop(self.pcap, cnt, _loop_callback, <unsigned char*>&ctx)
        if err < 0:
            raise Error(err, cpcap.pcap_geterr(self.pcap).decode)

    def dispatch(self, int cnt, callback: Callable[[Pkthdr, bytes], None]) -> None:
        """Process packets from a live capture or savefile."""
        self._check_closed()

        cdef _LoopCallbackContext ctx
        ctx.pcap = <PyObject*>self
        ctx.func = <PyObject*>callback

        with nogil:
            err = cpcap.pcap_dispatch(self.pcap, cnt, _loop_callback, <unsigned char*>&ctx)
        if err < 0:
            raise Error(err, cpcap.pcap_geterr(self.pcap).decode())

    def breakloop(self) -> None:
        """Force a :meth:`dispatch` or :meth:`loop` call to return."""
        self._check_closed()

        cpcap.pcap_breakloop(self.pcap)

    def getnonblock(self) -> bool:
        """Get the state of non-blocking mode."""
        self._check_closed()

        cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
        result = cpcap.pcap_getnonblock(self.pcap, errbuf)
        if result < 0:
            raise Error(result, errbuf.decode())

        return bool(result)

    def setnonblock(self, nonblock: bool) -> None:
        """Set the state of non-blocking mode."""
        self._check_closed()

        cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
        result = cpcap.pcap_setnonblock(self.pcap, nonblock, errbuf)
        if result < 0:
            raise Error(result, errbuf.decode())

    def set_snaplen(self, snaplen: int) -> None:
        """Set the snapshot length for a not-yet-Pcap."""
        self._check_closed()

        err = cpcap.pcap_set_snaplen(self.pcap, snaplen)
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def set_promisc(self, promisc: bool) -> None:
        """Set promiscuous mode for a not-yet-activated Pcap."""
        self._check_closed()

        err = cpcap.pcap_set_promisc(self.pcap, promisc)
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def can_set_rfmon(self) -> bool:
        """Check whether monitor mode can be set for a not-yet-activated Pcap."""
        self._check_closed()

        result = cpcap.pcap_can_set_rfmon(self.pcap)
        if result < 0:
            if result == ErrorCode.ERROR:
                raise Error(result, cpcap.pcap_geterr(self.pcap).decode())

            raise Error(result, cpcap.pcap_statustostr(result).decode())

        return bool(result)

    def set_rfmon(self, rfmon: bool) -> None:
        """Set monitor mode for a not-yet-activated Pcap."""
        self._check_closed()

        err = cpcap.pcap_set_rfmon(self.pcap, rfmon)
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def set_timeout(self, double timeout: float) -> None:
        """
        Set the packet buffer timeout for a not-yet-activated Pcap (In seconds as a floating point
        number).
        """
        self._check_closed()

        err = cpcap.pcap_set_timeout(self.pcap, int(timeout * 1000))
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def set_tstamp_type(self, tstamp_type: TstampType) -> None:
        """Set the time stamp type to be used by a Pcap."""
        self._check_closed()

        err = cpcap.pcap_set_tstamp_type(self.pcap, tstamp_type)
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def set_immediate_mode(self, immediate_mode: bool) -> None:
        """Set immediate mode for a not-yet-activated Pcap."""
        self._check_closed()

        err = cpcap.pcap_set_immediate_mode(self.pcap, immediate_mode)
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def set_buffer_size(self, buffer_size: int) -> None:
        """Set the buffer size for a not-yet-activated Pcap."""
        self._check_closed()

        err = cpcap.pcap_set_buffer_size(self.pcap, buffer_size)
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def set_tstamp_precision(self, tstamp_precision: TstampPrecision) -> None:
        """Set the time stamp precision returned in captures."""
        self._check_closed()

        err = cpcap.pcap_set_tstamp_precision(self.pcap, tstamp_precision)
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def get_tstamp_precision(self) -> TstampPrecision:
        """Get the time stamp precision returned in captures."""
        self._check_closed()

        return TstampPrecision(cpcap.pcap_get_tstamp_precision(self.pcap))


    """
    Set capture protocol for a not-yet-activated Pcap.

    Availability: Linux
    """
    def set_protocol_linux(self, protocol: int) -> None:
        self._check_closed()

        if not sys.platform.startswith("linux"):
            raise NotSupportedError

        err = cpcap.pcap_set_protocol_linux(self.pcap, protocol)
        if err < 0:
            raise Error(err, cpcap.pcap_statustostr(err).decode())

    def activate(self) -> None:
        """Activate a Pcap."""
        self._check_closed()

        err = cpcap.pcap_activate(self.pcap)
        if err < 0:
            raise Error(err, cpcap.pcap_geterr(self.pcap).decode())
        elif err > 0:
            warnings.warn(Warning(err, cpcap.pcap_geterr(self.pcap).decode()))

    def list_tstamp_types(self) -> List[TstampType]:
        """Get a list of time stamp types supported by a capture device."""
        self._check_closed()

        cdef int* tstamp_types
        cdef int num = cpcap.pcap_list_tstamp_types(self.pcap, &tstamp_types)
        if num < 0:
            raise Error(num, cpcap.pcap_geterr(self.pcap).decode())

        try:
            result = []
            for tstamp_type in tstamp_types[:num]:
                result.append(TstampType(tstamp_type))

            return result
        finally:
            cpcap.pcap_free_tstamp_types(tstamp_types)

    def datalink(self) -> DatalinkType:
        """Get the link-layer header type."""
        self._check_closed()

        result = cpcap.pcap_datalink(self.pcap)
        if result < 0:
            raise Error(result, cpcap.pcap_statustostr(result).decode())

        try:
            return DatalinkType(result)
        except ValueError:
            return result

    def list_datalinks(self) -> List[DatalinkType]:
        """Get a list of link-layer header types supported by a Pcap."""
        self._check_closed()

        cdef int* datalinks
        cdef int num = cpcap.pcap_list_datalinks(self.pcap, &datalinks)
        if num < 0:
            raise Error(num, cpcap.pcap_geterr(self.pcap).decode())

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

    def set_datalink(self, datalink: DatalinkType) -> None:
        """Set the link-layer header type to be used by a Pcap."""
        self._check_closed()

        result = cpcap.pcap_set_datalink(self.pcap, datalink)
        if result < 0:
            raise Error(result, cpcap.pcap_geterr(self.pcap).decode())

        return result

    def snapshot(self) -> int:
        """Get the snapshot length."""
        self._check_closed()

        result = cpcap.pcap_snapshot(self.pcap)
        if result < 0:
            raise Error(result, cpcap.pcap_statustostr(result).decode())

        return result

    def is_swapped(self) -> bool:
        """Find out whether a savefile has the native byte order."""
        self._check_closed()

        result = cpcap.pcap_is_swapped(self.pcap)
        if result < 0:
            raise Error(result, cpcap.pcap_statustostr(result).decode())

        return result

    def compile(self, filter_: str, optimize: bool=True, netmask: Optional[int]=None) -> BpfProgram:
        """
        Compile a filter expression.

        If you don't supply a netmask, for a live capture, compile will try to use :func:`lookupnet`
        to figure out the netmask, falling back to :data:`NETMASK_UNKNWON`, for dead or capture
        files, it will use :data:`NETMASK_UNKNWON`.
        """
        # Note that if we add support for libpcap older than 1.8, we need to add a global lock here
        cdef char errbuf[cpcap.PCAP_ERRBUF_SIZE]
        cdef cpcap.bpf_u_int32 net
        cdef cpcap.bpf_u_int32 mask

        self._check_closed()

        if netmask is None:
            if self.type is PcapType.LIVE:
                err = cpcap.pcap_lookupnet(self.source.encode(), &net, &mask, errbuf)
                if err < 0:
                    raise Error(err, errbuf.decode())

                netmask = mask
                print(netmask)
            else:
                netmask = NETMASK_UNKNOWN

        cdef BpfProgram bpf_prog = BpfProgram.__new__(BpfProgram)
        err = cpcap.pcap_compile(self.pcap, &bpf_prog.bpf_prog, filter_.encode(), optimize, netmask)
        if err < 0:
            raise Error(err, cpcap.pcap_geterr(self.pcap).decode())

        return bpf_prog

    def setfilter(self, filter: Union[BpfProgram, str], *, optimize=True, netmask=None) -> None:
        """
        Set the BPF filter.

        You can pass either a :class:`BpfProgram` or a :class:`str` that will be passed to
        :meth:`compile` (The keyword arguments are only used when passing a :class:`str`).
        """
        self._check_closed()
        cdef BpfProgram bpf_prog

        if isinstance(filter, BpfProgram):
            bpf_prog = filter
        else:
            bpf_prog = self.compile(filter, optimize=optimize, netmask=netmask)

        err = cpcap.pcap_setfilter(self.pcap, &bpf_prog.bpf_prog)
        if err < 0:
            raise Error(err, cpcap.pcap_geterr(self.pcap).decode())

    def setdirection(self, d: Direction) -> None:
        """Set the direction for which packets will be captured."""
        self._check_closed()

        err = cpcap.pcap_setdirection(self.pcap, d)
        if err < 0:
            raise Error(err, cpcap.pcap_geterr(self.pcap).decode())

    def stats(self) -> Stat:
        """Get capture statistics."""
        self._check_closed()

        cdef Stat stat = Stat.__new__(Stat)
        err = cpcap.pcap_stats(self.pcap, &stat.stat)
        if err < 0:
            raise Error(err, cpcap.pcap_geterr(self.pcap).decode())

        return stat

    def dump_open(self, fname: os.PathLike) -> Dumper:
        """Open a file to which to write packets."""
        self._check_closed()

        cdef Dumper dumper = Dumper.__new__(Dumper)
        dumper.dumper = cpcap.pcap_dump_open(self.pcap, os.fsencode(fname))
        if not dumper.dumper:
            raise Error(ErrorCode.ERROR, cpcap.pcap_geterr(self.pcap).decode())

        return dumper

    def dump_open_append(self, fname: os.PathLike) -> Dumper:
        """
        Open a file to which to write packets but, if the file already exists, and is a pcap file
        with the same byte order as the host opening the file, and has the same time stamp
        precision, link-layer header type, and snapshot length as p, it will write new packets at
        the end of the file.
        """
        self._check_closed()

        cdef Dumper dumper = Dumper.__new__(Dumper)
        dumper.dumper = cpcap.pcap_dump_open_append(self.pcap, os.fsencode(fname))
        if not dumper.dumper:
            raise Error(ErrorCode.ERROR, cpcap.pcap_geterr(self.pcap).decode())

        return dumper

    def inject(self, const unsigned char[::1] buf) -> int:
        """
        Transmit a packet. *buf* is a object supporting the buffer protocol, e.g. :class:`bytes`,
        :class:`bytearray`.

        .. note::

           :meth:`sendpacket` is like :meth:`inject`, but it returns 0 on success, rather than
           returning the number of bytes written. (pcap_inject() comes from OpenBSD;
           pcap_sendpacket() comes from WinPcap/Npcap. Both are provided for compatibility.)
        """
        self._check_closed()

        result = cpcap.pcap_inject(self.pcap, &buf[0], <size_t>buf.shape[0])
        if result < 0:
            raise Error(ErrorCode.ERROR, cpcap.pcap_geterr(self.pcap).decode())

        return result

    def sendpacket(self, const unsigned char[::1] buf) -> None:
        """
        Transmit a packet. *buf* is a object supporting the buffer protocol, e.g. :class:`bytes`,
        :class:`bytearray`.

        .. note::

           :meth:`sendpacket` is like :meth:`inject`, but it returns 0 on success, rather than
           returning the number of bytes written. (pcap_inject() comes from OpenBSD;
           pcap_sendpacket() comes from WinPcap/Npcap. Both are provided for compatibility.)
        """
        self._check_closed()

        result = cpcap.pcap_sendpacket(self.pcap, &buf[0], <int>buf.shape[0])
        if result < 0:
            raise Error(ErrorCode.ERROR, cpcap.pcap_geterr(self.pcap).decode())


    def getevent(self) -> int:
        """
        Get an event ``HANDLE`` that can be used to unblock pcap.

        Availability: Windows
        """
        self._check_closed()

        if sys.platform != "win32":
            raise NotSupportedError

        return <uintptr_t>cpcap.pcap_getevent(self.pcap)

    def get_selectable_fd(self) -> int:
        """
        Get a file descriptor on which a ``select()`` can be done for a live capture.

        Availability: Unix (POSIX)
        """
        self._check_closed()

        if os.name != "posix":
            raise NotSupportedError

        return cpcap.pcap_get_selectable_fd(self.pcap)

    def get_required_select_timeout(self) -> Optional[float]:
        """
        Get a timeout to be used when doing ``select()`` for a live capture.

        Availability: Unix (POSIX)
        """
        self._check_closed()

        if os.name != "posix":
            raise NotSupportedError

        timeout = cpcap.pcap_get_required_select_timeout(self.pcap)

        if timeout is not NULL:
            return timeout.tv_sec + timeout.tv_usec / 1000000

        return None

    def set_pre_config(self, *,
        snaplen: Optional[int]=None,
        promisc: Optional[bool]=None,
        timeout: Optional[float]=None,
        rfmon: Optional[bool]=None,
        immediate_mode: Optional[bool]=None,
        buffer_size: Optional[int]=None,
        tstamp_type: Optional[TstampType]=None,
        tstamp_precision: Optional[TstampPrecision]=None,
        protocol_linux: Optional[int]=None,
    ) -> None:
        """Set pre activation configuration from keyword arguments."""

        if snaplen is not None:
            self.set_snaplen(snaplen)

        if promisc is not None:
            self.set_promisc(promisc)

        if timeout is not None:
            self.set_timeout(timeout)

        if rfmon is not None:
            self.set_rfmon(rfmon)

        if immediate_mode is not None:
            self.set_immediate_mode(immediate_mode)

        if buffer_size is not None:
            self.set_buffer_size(buffer_size)

        if tstamp_type is not None:
            self.set_tstamp_type(tstamp_type)

        if tstamp_precision is not None:
            self.set_tstamp_precision(tstamp_precision)

        if protocol_linux is not None:
            self.set_protocol_linux(protocol_linux)

    def set_config(self, *,
        filter: Optional[Union[BpfProgram, str]]=None,
        direction: Optional[Direction]=None,
        datalink: Optional[DatalinkType]=None,
        nonblock: Optional[bool]=None,
    ) -> None:
        """Set post activation configuration from keyword arguments."""

        if filter is not None:
            self.setfilter(filter)

        if direction is not None:
            self.setdirection(direction)

        if datalink is not None:
            self.set_datalink(datalink)

        if nonblock is not None:
            self.setnonblock(nonblock)


class BpfDumpType(enum.IntEnum):
    DEFAULT = 0
    MULTILINE = 1
    C_ARRAY = 2
    DISASSEMBLY = 3


cdef _bpf_image_lock = threading.Lock()


cdef _bpf_insn_to_tuple(cpcap.bpf_insn insn):
    return (int(insn.code), int(insn.jt), int(insn.jf), int(insn.k))


cdef class BpfProgram:
    """
    A BPF filter program for :meth:`Pcap.setfilter`.

    Can be created via :meth:`Pcap.compile` or :meth:`loads` or by supplying a list of tuples of the
    form ``[(code, jt, jf, k), ...]``.
    """
    cdef cpcap.bpf_program bpf_prog
    cdef bint use_free

    def __init__(self, list_: list):
        if len(list_) > 2**32-1:
            raise ValueError("BPF too long")

        if self.bpf_prog.bf_insns:
            if self.use_free:
                free(self.bpf_prog.bf_insns)
            else:
                cpcap.pcap_freecode(&self.bpf_prog)

        self.use_free = True
        self.bpf_prog.bf_len = <unsigned int>len(list_)
        self.bpf_prog.bf_insns = <cpcap.bpf_insn*>malloc(self.bpf_prog.bf_len * sizeof(cpcap.bpf_insn))

        for i, v in enumerate(list_):
            self.bpf_prog.bf_insns[i].code = int(v[0])
            self.bpf_prog.bf_insns[i].jt = int(v[1])
            self.bpf_prog.bf_insns[i].jf = int(v[2])
            self.bpf_prog.bf_insns[i].k = int(v[3])

    def __dealloc__(self):
        if self.bpf_prog.bf_insns:
            if self.use_free:
                free(self.bpf_prog.bf_insns)
            else:
                cpcap.pcap_freecode(&self.bpf_prog)

    def __repr__(self):
        return f"<BpfProgram with {self.bpf_prog.bf_len} instructions>"

    def __getitem__(self, key):
        if isinstance(key, int):
            if key < 0:
                key += self.bpf_prog.bf_len

            if key >= self.bpf_prog.bf_len:
                raise IndexError("index out of range")

            return _bpf_insn_to_tuple(self.bpf_prog.bf_insns[key])
        elif isinstance(key, slice):
            start, stop, step = key.indices(self.bpf_prog.bf_len)

            result = []
            for i in range(start, stop, step):
                result.append(_bpf_insn_to_tuple(self.bpf_prog.bf_insns[i]))

            return result
        else:
            raise TypeError(f"indices must be integers or slices, not {type(key)}")

    def __len__(self):
        return self.bpf_prog.bf_len

    def __iter__(self):
        for insn in self.bpf_prog.bf_insns[:self.bpf_prog.bf_len]:
            yield _bpf_insn_to_tuple(insn)

    def offline_filter(self, pkt_header: Pkthdr, pkt_data: bytes) -> bool:
        """Check whether a filter matches a packet."""
        return cpcap.pcap_offline_filter(&self.bpf_prog, &pkt_header.pkthdr, pkt_data)

    def dumps(self, type_: BpfDumpType=BpfDumpType.DEFAULT) -> str:
        """
        Dump the BPF filter in the requested format.

        Formats:
        * ``DEFAULT`` - The format used by iptables, tc-bpf, etc.
        * ``MULTILINE`` - Like ``DEFAULT`` but with each element on a separate line.
        * ``C_ARRAY`` - As an array suitable for embedding in C.
        * ``DISASSEMBLY`` - Human readable disassembly.
        """
        result = []

        if type_ == BpfDumpType.DEFAULT:
            result.append(f"{self.bpf_prog.bf_len},")

            for insn in self.bpf_prog.bf_insns[:self.bpf_prog.bf_len-1]:
                result.append(f"{insn.code} {insn.jt} {insn.jf} {insn.k},")

            insn = self.bpf_prog.bf_insns[self.bpf_prog.bf_len-1]
            result.append(f"{insn.code} {insn.jt} {insn.jf} {insn.k}")

            return ''.join(result)

        elif type_ == BpfDumpType.MULTILINE:
            result.append(f"{self.bpf_prog.bf_len}")
            for insn in self.bpf_prog.bf_insns[:self.bpf_prog.bf_len]:
                result.append(f"{insn.code} {insn.jt} {insn.jf} {insn.k}")
            return '\n'.join(result)

        elif type_ == BpfDumpType.C_ARRAY:
            for insn in self.bpf_prog.bf_insns[:self.bpf_prog.bf_len]:
                result.append(f"{{ 0x{insn.code:x}, {insn.jt}, {insn.jf}, 0x{insn.k:08x} }},")
            return '\n'.join(result)

        elif type_ == BpfDumpType.DISASSEMBLY:
            with _bpf_image_lock:
                for i in range(self.bpf_prog.bf_len):
                    result.append(cpcap.bpf_image(&self.bpf_prog.bf_insns[i], i).decode())
                return '\n'.join(result)

        else:
            raise ValueError(f"unknown type {type_!r}")

    @staticmethod
    def loads(s: str) -> BpfProgram:
        """
        Load a BPF filter in the format used by iptables, tc-bpf, etc. (The ``DEFAULT`` format from
        dumps).
        """
        cdef BpfProgram self = BpfProgram.__new__(BpfProgram)

        length, *insns = s.split(',')
        length = int(length)

        if len(insns) != length:
            raise ValueError("invalid BPF bytecode")

        self.use_free = True
        self.bpf_prog.bf_len = length
        self.bpf_prog.bf_insns = <cpcap.bpf_insn*>malloc(self.bpf_prog.bf_len * sizeof(cpcap.bpf_insn))

        for i, insn in enumerate(insns):
            code, jt, jf, k = insn.split(None, 4)
            self.bpf_prog.bf_insns[i].code = int(code)
            self.bpf_prog.bf_insns[i].jt = int(jt)
            self.bpf_prog.bf_insns[i].jf = int(jf)
            self.bpf_prog.bf_insns[i].k = int(k)

        return self


cdef class Dumper:
    """Dumper represents a capture savefile."""
    cdef cpcap.pcap_dumper_t* dumper

    def __init__(self):
        raise TypeError(f"cannot create '{self.__class__.__name__}' instances")

    def __dealloc__(self):
        if self.dumper:
            warnings.warn(f"unclosed Dumper {self!r}", ResourceWarning, source=self)
            self.close()

    cpdef close(self):
        """Close the Dumper."""
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

    def dump(self, Pkthdr pkt_header: Pkthdr, pkt_data) -> None:
        """Write a packet to a capture file."""
        self._check_closed()

        cpcap.pcap_dump(<unsigned char*>self.dumper, &pkt_header.pkthdr, pkt_data)

    def ftell(self) -> int:
        """Get the current file offset for a savefile being written."""
        self._check_closed()

        result = cpcap.pcap_dump_ftell64(self.dumper)
        if result == cpcap.PCAP_ERROR:
            raise Error(result, cpcap.pcap_statustostr(<int>result).decode())

        return result


def lib_version() -> str:
    """Get the version information for libpcap."""
    return cpcap.pcap_lib_version().decode()
