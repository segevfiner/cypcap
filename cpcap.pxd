from csocket cimport sockaddr

cdef extern from "<pcap/pcap.h>":
    enum:
        PCAP_ERRBUF_SIZE

    enum:
        PCAP_CHAR_ENC_LOCAL
        PCAP_CHAR_ENC_UTF_8

    ctypedef unsigned int bpf_u_int32

    struct pcap:
        pass

    ctypedef pcap pcap_t

    struct pcap_if:
        pcap_if* next
        char* name
        char* description
        pcap_addr* addresses
        bpf_u_int32 flags

    enum:
        PCAP_IF_LOOPBACK
        PCAP_IF_UP
        PCAP_IF_RUNNING
        PCAP_IF_WIRELESS
        PCAP_IF_CONNECTION_STATUS
        PCAP_IF_CONNECTION_STATUS_UNKNOWN
        PCAP_IF_CONNECTION_STATUS_CONNECTED
        PCAP_IF_CONNECTION_STATUS_DISCONNECTED
        PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE

    ctypedef pcap_if pcap_if_t

    struct pcap_addr:
        pcap_addr* next
        sockaddr* addr
        sockaddr* netmask
        sockaddr* broadaddr
        sockaddr* dstaddr

    int pcap_init(unsigned int, char *)

    pcap_t *pcap_create(const char *, char *)

    void pcap_close(pcap_t *)

    int	pcap_findalldevs(pcap_if_t **, char *)

    void pcap_freealldevs(pcap_if_t *)

    const char *pcap_lib_version()
