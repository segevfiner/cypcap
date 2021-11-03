import socket
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
        pcap.set_timeout(1000)
        pcap.activate()
        yield pcap


@pytest.fixture
def sender_pcap(interface):
    with cypcap.create(interface) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1000)
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


def test_inject_capture(pcap, sender_pcap, echo_pkt):
    sender_pcap.inject(bytes(echo_pkt))

    for pkthdr, data in pcap:
        if pkthdr is None:
            continue

        captured_pkthdr, captured_pkt = pkthdr, dpkt.ethernet.Ethernet(data)
        break

    assert bytes(echo_pkt) == bytes(captured_pkt)
    assert repr(captured_pkthdr)


def test_create_interface_obj(interface_obj, sender_pcap, echo_pkt):
     with cypcap.create(interface_obj) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1000)
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
    with cypcap.open_live(interface, 65536, True, 1000) as pcap:
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
        assert pcap.compile("tcp", True, cypcap.NETMASK_UNKNOWN) is not None


def test_sendpacket_capture(pcap, sender_pcap, echo_pkt):
    sender_pcap.sendpacket(bytes(echo_pkt))

    for pkthdr, data in pcap:
        if pkthdr is None:
            continue

        captured_pkt = dpkt.ethernet.Ethernet(data)
        break

    assert bytes(echo_pkt) == bytes(captured_pkt)


def test_dump(pcap, sender_pcap, echo_pkt, tmp_path):
    dump_file = tmp_path / "dump.pcap"

    packets = []
    for i in range(1, 5):
        pkt = copy.deepcopy(echo_pkt)
        packets.append(pkt)
        sender_pcap.inject(bytes(pkt))

    captured = 0
    with pcap.dump_open(dump_file) as dump:
        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            dump.dump(pkthdr, data)
            captured += 1

            if captured == 4:
                break

    with cypcap.open_offline(dump_file) as dump:
        for i, (pkthdr, data) in enumerate(dump):
            assert bytes(dpkt.ethernet.Ethernet(data)) == bytes(packets[i])


def test_nonexistent_interface():
    with pytest.raises(cypcap.Error):
        pcap = cypcap.create("nonexistent0")
        pcap.activate()


def test_lib_version():
    assert isinstance(cypcap.lib_version(), str)
