import os
import socket
from datetime import datetime, timezone
import copy

import dpkt
import netifaces
import pytest

import cypcap


@pytest.fixture
def echo_pkt(interface_addresses):
    pkt = dpkt.ethernet.Ethernet(
        dst=b"\x01\x02\x03\x04\x05\x06",
        src=bytes.fromhex(interface_addresses[netifaces.AF_PACKET][0]['addr'].replace(":", '')),
    )

    # TODO except KeyError
    ip = pkt.data = dpkt.ip.IP(
        dst=b"\x08\x08\x08\x08",
        src=socket.inet_pton(socket.AF_INET, interface_addresses[netifaces.AF_INET][0]['addr']),
        p=dpkt.ip.IP_PROTO_ICMP,
    )

    icmp = ip.data = dpkt.icmp.ICMP(
        type=dpkt.icmp.ICMP_ECHO,
    )

    icmp.data = dpkt.icmp.ICMP.Echo(
        id=1234,
        seq=1,
        data=b"ABCDEF",
    )

    return pkt


@pytest.fixture
def pcap(interface):
    with cypcap.create(interface) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1)
        pcap.activate()
        yield pcap


@pytest.fixture
def sender_pcap(interface):
    with cypcap.create(interface) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1)
        pcap.activate()
        yield pcap


@pytest.fixture
def interface_obj(interface):
    return next((dev for dev in cypcap.findalldevs() if dev.name == interface), None)


def test_datalink_description():
    assert cypcap.DatalinkType.EN10MB.description == "Ethernet"


def test_errorcode_description():
    assert cypcap.ErrorCode.ERROR.description == "Generic error"


def test_tstamptype_props():
    assert cypcap.TstampType.HOST.name == "host"
    assert cypcap.TstampType.HOST.description == "Host"


PKTHDR_TS = 1636819043.182649
PKTHDR_LEN = 1500


def test_pkthdr_init():
    pkthdr = cypcap.Pkthdr(PKTHDR_TS, PKTHDR_LEN, PKTHDR_LEN)
    assert pkthdr.ts == PKTHDR_TS


def test_pkthdr_ts_datetime():
    pkthdr = cypcap.Pkthdr(PKTHDR_TS, PKTHDR_LEN, PKTHDR_LEN)

    assert pkthdr.ts_datetime == datetime.fromtimestamp(PKTHDR_TS)

    now = datetime.now()
    pkthdr.ts_datetime = now
    assert pkthdr.ts_datetime == now


def test_pkthdr_ts_utcdatetime():
    pkthdr = cypcap.Pkthdr(PKTHDR_TS, PKTHDR_LEN, PKTHDR_LEN)

    assert pkthdr.ts_utcdatetime == datetime.fromtimestamp(PKTHDR_TS, timezone.utc)

    now = datetime.now(timezone.utc)
    pkthdr.ts_utcdatetime = now
    assert pkthdr.ts_utcdatetime == now


def test_findalldevs(interface):
    devs = cypcap.findalldevs()

    dev = next((dev for dev in devs if dev.name == interface), None)
    assert dev is not None

    assert repr(dev)
    assert len(dev.addresses) > 0
    assert repr(dev.addresses[0])
    assert dev.flags


def test_lookupnet(interface, interface_addresses):
    network, netmask = cypcap.lookupnet(interface)
    assert interface_addresses[netifaces.AF_INET][0]['addr'] == socket.inet_ntop(socket.AF_INET, network.to_bytes(4, 'little'))
    assert interface_addresses[netifaces.AF_INET][0]['netmask'] == socket.inet_ntop(socket.AF_INET, netmask.to_bytes(4, 'little'))


def test_lookupnet_obj(interface_obj, interface_addresses):
    network, netmask = cypcap.lookupnet(interface_obj)
    assert interface_addresses[netifaces.AF_INET][0]['addr'] == socket.inet_ntop(socket.AF_INET, network.to_bytes(4, 'little'))
    assert interface_addresses[netifaces.AF_INET][0]['netmask'] == socket.inet_ntop(socket.AF_INET, netmask.to_bytes(4, 'little'))


def test_inject_capture(pcap, sender_pcap, echo_pkt):
    sender_pcap.inject(bytes(echo_pkt))

    for pkthdr, data in pcap:
        if pkthdr is None:
            continue

        captured_pkthdr, captured_pkt = pkthdr, dpkt.ethernet.Ethernet(data)
        break

    assert bytes(echo_pkt) == bytes(captured_pkt)
    assert repr(captured_pkthdr)


def test_sendpacket_capture(pcap, sender_pcap, echo_pkt):
    sender_pcap.sendpacket(bytes(echo_pkt))

    for pkthdr, data in pcap:
        if pkthdr is None:
            continue

        captured_pkt = dpkt.ethernet.Ethernet(data)
        break

    assert bytes(echo_pkt) == bytes(captured_pkt)


def test_stats(pcap, sender_pcap, echo_pkt):
    sender_pcap.inject(bytes(echo_pkt))

    for pkthdr, data in pcap:
        if pkthdr is None:
            continue

        captured_pkthdr, captured_pkt = pkthdr, dpkt.ethernet.Ethernet(data)
        break

    assert bytes(echo_pkt) == bytes(captured_pkt)

    stats = pcap.stats()
    assert repr(stats)
    assert stats.recv >= 1
    assert stats.drop == 0
    assert stats.ifdrop == 0


def test_setfilter_bpf(pcap, sender_pcap, echo_pkt):
    sender_pcap.sendpacket(bytes(echo_pkt))

    bpf = pcap.compile("tcp", True)
    pcap.setfilter(bpf)
    pcap.setnonblock(True)

    assert next(pcap) == (None, None)


def test_setfilter_str(pcap, sender_pcap, echo_pkt):
    sender_pcap.sendpacket(bytes(echo_pkt))

    pcap.setfilter("tcp")
    pcap.setnonblock(True)

    assert next(pcap) == (None, None)


def test_setdirection(pcap, sender_pcap, echo_pkt):
    # TODO setdirection is not available on all platforms, so we might later need to add a
    # try/except here to skip this test if it is not supported
    sender_pcap.sendpacket(bytes(echo_pkt))

    pcap.setdirection(cypcap.Direction.OUT)

    for pkthdr, data in pcap:
        if pkthdr is None:
            continue

        captured_pkthdr, captured_pkt = pkthdr, dpkt.ethernet.Ethernet(data)
        break

    assert bytes(echo_pkt) == bytes(captured_pkt)
    assert repr(captured_pkthdr)


def test_loop(pcap, sender_pcap, echo_pkt):
    sender_pcap.inject(bytes(echo_pkt))

    def callback(pkthdr, data):
        pkt = dpkt.ethernet.Ethernet(data)
        assert bytes(echo_pkt) == bytes(pkt)

    pcap.loop(1, callback)


def test_breakloop(pcap, sender_pcap, echo_pkt):
    sender_pcap.inject(bytes(echo_pkt))
    sender_pcap.inject(bytes(echo_pkt))

    captured = 0
    def callback(pkthdr, data):
        nonlocal captured
        pkt = dpkt.ethernet.Ethernet(data)
        assert bytes(echo_pkt) == bytes(pkt)
        captured += 1
        pcap.breakloop()

    with pytest.raises(cypcap.Error, match="BREAK"):
        pcap.loop(2, callback)

    assert captured == 1


def test_loop_exception(pcap, sender_pcap, echo_pkt):
    sender_pcap.inject(bytes(echo_pkt))

    def callback(pkthdr, data):
        raise ValueError(1234)

    with pytest.raises(ValueError, match="1234"):
        pcap.loop(1, callback)


def test_dispatch(pcap, sender_pcap, echo_pkt):
    sender_pcap.inject(bytes(echo_pkt))

    def callback(pkthdr, data):
        pkt = dpkt.ethernet.Ethernet(data)
        assert bytes(echo_pkt) == bytes(pkt)

    pcap.dispatch(1, callback)


def test_create_interface_obj(interface_obj, sender_pcap, echo_pkt):
     with cypcap.create(interface_obj) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1)
        pcap.activate()

        sender_pcap.inject(bytes(echo_pkt))

        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            captured_pkthdr, captured_pkt = pkthdr, dpkt.ethernet.Ethernet(data)
            break

        assert bytes(echo_pkt) == bytes(captured_pkt)
        assert repr(captured_pkthdr)


def test_open_live(interface, sender_pcap, echo_pkt):
    with cypcap.open_live(interface, 65536, True, 1) as pcap:
        sender_pcap.inject(bytes(echo_pkt))

        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            captured_pkthdr, captured_pkt = pkthdr, dpkt.ethernet.Ethernet(data)
            break

        assert bytes(echo_pkt) == bytes(captured_pkt)
        assert repr(captured_pkthdr)


def test_open_live_obj(interface_obj, sender_pcap, echo_pkt):
    with cypcap.open_live(interface_obj, 65536, True, 1) as pcap:
        sender_pcap.inject(bytes(echo_pkt))

        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            captured_pkthdr, captured_pkt = pkthdr, dpkt.ethernet.Ethernet(data)
            break

        assert bytes(echo_pkt) == bytes(captured_pkt)
        assert repr(captured_pkthdr)


def test_open_dead():
    with cypcap.open_dead(cypcap.DatalinkType.EN10MB, 65536) as pcap:
        assert pcap.compile("tcp", True) is not None


def test_open_offline(tmp_path, echo_pkt):
    packets = []
    for i in range(1, 5):
        pkt = copy.deepcopy(echo_pkt)
        pkt.data.data.data.seq = i
        packets.append(pkt)

    dump_file = tmp_path / "dump.pcap"
    with open(dump_file, "wb") as f:
        writer = dpkt.pcap.Writer(f, 65536)
        for pkt in packets:
            writer.writepkt(pkt)

    with cypcap.open_offline(dump_file) as dump:
        assert not dump.is_swapped()
        for i, (pkthdr, data) in enumerate(dump):
            assert bytes(dpkt.ethernet.Ethernet(data)) == bytes(packets[i])


def test_capture_dump(pcap, sender_pcap, echo_pkt, tmp_path):
    dump_file = tmp_path / "dump.pcap"

    packets = []
    for i in range(1, 5):
        pkt = copy.deepcopy(echo_pkt)
        pkt.data.data.data.seq = i
        packets.append(pkt)
        sender_pcap.inject(bytes(pkt))

    captured = 0
    with pcap.dump_open(dump_file) as dump:
        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            dump.dump(pkthdr, data)
            captured += 1
            assert dump.ftell() > 0

            if captured == 4:
                break

    with cypcap.open_offline(dump_file) as dump:
        for i, (pkthdr, data) in enumerate(dump):
            assert bytes(dpkt.ethernet.Ethernet(data)) == bytes(packets[i])


def test_capture_dump_append(pcap, sender_pcap, echo_pkt, tmp_path):
    dump_file = tmp_path / "dump.pcap"

    packets = []
    for i in range(1, 3):
        pkt = copy.deepcopy(echo_pkt)
        pkt.data.data.data.seq = i
        packets.append(pkt)
        sender_pcap.inject(bytes(pkt))

    captured = 0
    with pcap.dump_open(dump_file) as dump:
        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            dump.dump(pkthdr, data)
            captured += 1
            assert dump.ftell() > 0

            if captured == 2:
                break

    for i in range(3, 5):
        pkt = copy.deepcopy(echo_pkt)
        pkt.data.data.data.seq = i
        packets.append(pkt)
        sender_pcap.inject(bytes(pkt))

    captured = 0
    with pcap.dump_open_append(dump_file) as dump:
        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            dump.dump(pkthdr, data)
            captured += 1
            assert dump.ftell() > 0

            if captured == 2:
                break

    with cypcap.open_offline(dump_file) as dump:
        for i, (pkthdr, data) in enumerate(dump):
            assert bytes(dpkt.ethernet.Ethernet(data)) == bytes(packets[i])


def test_capture_dump_nanoseconds(interface, sender_pcap, echo_pkt, tmp_path):
    dump_file = tmp_path / "dump.pcap"

    captured = 0
    with cypcap.create(interface) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1)
        pcap.set_tstamp_precision(cypcap.TstampPrecision.NANO)
        pcap.activate()

        assert pcap.get_tstamp_precision() == cypcap.TstampPrecision.NANO

        packets = []
        for i in range(1, 5):
            pkt = copy.deepcopy(echo_pkt)
            pkt.data.data.data.seq = i
            packets.append(pkt)
            sender_pcap.inject(bytes(pkt))

        with pcap.dump_open(dump_file) as dump:
            for pkthdr, data in pcap:
                if pkthdr is None:
                    continue

                dump.dump(pkthdr, data)
                captured += 1
                assert dump.ftell() > 0

                if captured == 4:
                    break

    with cypcap.open_offline(dump_file, cypcap.TstampPrecision.NANO) as dump:
        assert dump.get_tstamp_precision() == cypcap.TstampPrecision.NANO

        for i, (pkthdr, data) in enumerate(dump):
            assert bytes(dpkt.ethernet.Ethernet(data)) == bytes(packets[i])


def test_set_tstamp_type(interface):
    with cypcap.create(interface) as pcap:
        tstamp_types = pcap.list_tstamp_types()
        pcap.set_tstamp_type(tstamp_types[0])


def test_datalink(pcap):
    assert pcap.datalink() == cypcap.DatalinkType.EN10MB


def test_set_datalink(pcap):
    datalinks = pcap.list_datalinks()
    pcap.set_datalink(datalinks[0])


def test_snapshot(pcap):
    assert pcap.snapshot() == 65536


def test_is_swapped(pcap):
    assert not pcap.is_swapped()


def test_nonblock(pcap):
    assert not pcap.getnonblock()
    pcap.setnonblock(True)
    assert pcap.getnonblock()

    assert next(pcap) == (None, None)


def test_set_immediate_mode(interface, echo_pkt, sender_pcap):
    with cypcap.create(interface) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_immediate_mode(True)
        pcap.activate()

        sender_pcap.sendpacket(bytes(echo_pkt))

        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            captured_pkt = dpkt.ethernet.Ethernet(data)
            break

        assert bytes(echo_pkt) == bytes(captured_pkt)


def test_set_buffer_size(interface):
    with cypcap.create(interface) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1)
        pcap.set_buffer_size(10 * 1024 * 1024)
        pcap.activate()


def test_can_set_rfmon(pcap):
    assert isinstance(pcap.can_set_rfmon(), bool)


def test_set_rfmon(interface):
    with cypcap.create(interface) as pcap:
        pcap.set_rfmon(False)
        pcap.activate()


def test_set_pre_config(interface):
    with cypcap.create(interface) as pcap:
        pcap.set_pre_config(
            snaplen=65536,
            promisc=True,
            timeout=1,
            rfmon=False,
            immediate_mode=True,
            buffer_size=10*1024*1024,
            tstamp_type=cypcap.TstampType.HOST,
            tstamp_precision=cypcap.TstampPrecision.NANO,
        )
        pcap.activate()


def test_set_config(pcap):
    bpf = pcap.compile("tcp", True)

    pcap.set_config(
        filter=bpf,
        direction=cypcap.Direction.INOUT,
        datalink=pcap.datalink(),
        nonblock=False,
    )


def test_list_tstamp_types(pcap):
    tstamp_types = pcap.list_tstamp_types()
    assert len(tstamp_types) > 0
    assert cypcap.TstampType.HOST in tstamp_types


def test_list_datalinks(pcap):
    datalinks = pcap.list_datalinks()
    assert len(datalinks) > 0
    assert cypcap.DatalinkType.EN10MB in datalinks


@pytest.mark.skipif(os.name != "posix", reason="Only supported on POSIX")
def test_get_selectable_fd(pcap):
    assert isinstance(pcap.get_selectable_fd(), int)


@pytest.mark.skipif(os.name != "posix", reason="Only supported on POSIX")
def test_get_required_select_timeout(pcap):
    timeout = pcap.get_required_select_timeout()
    assert timeout is None or isinstance(timeout, int)


def test_nonexistent_interface():
    with pytest.raises(cypcap.Error):
        pcap = cypcap.create("nonexistent0")
        pcap.activate()


def test_offline_filter(echo_pkt):
    pkthdr, data = cypcap.Pkthdr(0, len(echo_pkt), len(echo_pkt)), bytes(echo_pkt)
    bpf = cypcap.compile(cypcap.DatalinkType.EN10MB, 65536, "icmp", True, cypcap.NETMASK_UNKNOWN)
    assert bpf.offline_filter(pkthdr, data)
    bpf = cypcap.compile(cypcap.DatalinkType.EN10MB, 65536, "tcp", True, cypcap.NETMASK_UNKNOWN)
    assert not bpf.offline_filter(pkthdr, data)


@pytest.mark.parametrize("type_, expected", [
    (cypcap.BpfDumpType.DEFAULT, "2,40 0 0 12,6 0 0 65536"),
    (cypcap.BpfDumpType.MULTILINE, "2\n40 0 0 12\n6 0 0 65536"),
    (cypcap.BpfDumpType.C_ARRAY, "{ 0x28, 0, 0, 0x0000000c },\n{ 0x6, 0, 0, 0x00010000 },"),
    (cypcap.BpfDumpType.DISASSEMBLY, "(000) ldh      [12]\n(001) ret      #65536"),
])
def test_dumps(type_, expected):
    bpf = cypcap.BpfProgram([(40, 0, 0, 12), (6, 0, 0, 65536)])
    assert bpf.dumps(type_) == expected


@pytest.mark.parametrize("type_", list(cypcap.BpfDumpType))
def test_compile_dumps(type_):
    bpf = cypcap.compile(cypcap.DatalinkType.EN10MB, 65536, "tcp", True, cypcap.NETMASK_UNKNOWN)
    assert len(bpf.dumps(type_)) > 0


def test_compile_dumps_loads():
    bpf = cypcap.compile(cypcap.DatalinkType.EN10MB, 65536, "tcp", True, cypcap.NETMASK_UNKNOWN)
    disasm_dump1 = bpf.dumps(cypcap.BpfDumpType.DISASSEMBLY)

    dump = bpf.dumps()
    assert isinstance(dump, str)

    bpf2 = cypcap.BpfProgram.loads(dump)
    disasm_dump2 = bpf2.dumps(cypcap.BpfDumpType.DISASSEMBLY)

    assert disasm_dump1 == disasm_dump2


def test_compile_list_init():
    bpf = cypcap.compile(cypcap.DatalinkType.EN10MB, 65536, "tcp", True, cypcap.NETMASK_UNKNOWN)
    disasm_dump1 = bpf.dumps(cypcap.BpfDumpType.DISASSEMBLY)

    dump = list(bpf)
    assert isinstance(dump, list)
    assert len(dump) == len(bpf)

    bpf2 = cypcap.BpfProgram(dump)
    disasm_dump2 = bpf2.dumps(cypcap.BpfDumpType.DISASSEMBLY)

    assert disasm_dump1 == disasm_dump2


def test_compile_iter():
    bpf = cypcap.compile(cypcap.DatalinkType.EN10MB, 65536, "tcp", True, cypcap.NETMASK_UNKNOWN)
    disasm_dump = bpf.dumps(cypcap.BpfDumpType.DISASSEMBLY)

    dump = [insn for insn in bpf]
    assert len(dump) == len(disasm_dump.splitlines())


def test_lib_version():
    assert isinstance(cypcap.lib_version(), str)


@pytest.mark.parametrize("cls", [cypcap.Pcap, cypcap.Dumper])
def test_raising_init(cls):
    with pytest.raises(TypeError, match="cannot create"):
        cls()
