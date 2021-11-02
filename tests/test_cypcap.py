import socket
import copy

import dpkt
import netifaces
import pytest

import cypcap


@pytest.fixture(scope='session')
def echo_pkt(interface):
    addresses = netifaces.ifaddresses(interface)

    pkt = dpkt.ethernet.Ethernet(
        dst=b"\x01\x02\x03\x04\x05\x06",
        src=bytes.fromhex(addresses[netifaces.AF_PACKET][0]['addr'].replace(":", '')),
    )

    # TODO except KeyError
    ip = pkt.data = dpkt.ip.IP(
        dst=b"\x08\x08\x08\x08",
        src=socket.inet_pton(socket.AF_INET, addresses[netifaces.AF_INET][0]['addr']),
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


def test_inject_capture(pcap, sender_pcap, echo_pkt):
    sender_pcap.inject(bytes(echo_pkt))

    for pkthdr, data in pcap:
        if pkthdr is None:
            continue

        captured_pkt = dpkt.ethernet.Ethernet(data)
        break

    assert bytes(echo_pkt) == bytes(captured_pkt)


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
