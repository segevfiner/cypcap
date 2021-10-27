import socket
import dpkt
import netifaces
import cypcap


def test_basic_inject_capture(interface):
    addresses = netifaces.ifaddresses(interface)

    pkt = dpkt.ethernet.Ethernet(
        dst=b"\x01\x02\x03\x04\x05\x06",
        src=bytes.fromhex(addresses[netifaces.AF_PACKET][0]['addr'].replace(":", '')),
    )

    ip = pkt.data = dpkt.ip.IP(
        dst=b"\x08\x08\x08\x08",
        src=socket.inet_pton(socket.AF_INET, addresses[netifaces.AF_INET][0]['addr']),
        p=dpkt.ip.IP_PROTO_ICMP,
    )

    icmp = ip.data = dpkt.icmp.ICMP(
        type=dpkt.icmp.ICMP_ECHO,
    )

    icmp_echo = icmp.data = dpkt.icmp.ICMP.Echo(
        id=1234,
        seq=1,
        data=b"ABCDEF",
    )

    with cypcap.create(interface) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1000)
        pcap.activate()

        with cypcap.create(interface) as pcap2:
            pcap2.set_snaplen(65536)
            pcap2.set_promisc(True)
            pcap2.set_timeout(1000)
            pcap2.activate()
            pcap2.inject(bytes(pkt))

        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            captured_pkt = dpkt.ethernet.Ethernet(data)
            break

        assert bytes(pkt) == bytes(captured_pkt)
