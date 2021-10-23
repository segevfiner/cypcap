cdef extern from *:
    """
    #ifdef _WIN32
        #include <WinSock2.h>
    #else
        #include <sys/socket.h>
        #include <netinet/in.h>
    #endif
    """
    enum:
        AF_INET

    struct sockaddr:
        unsigned short sa_family
        char sa_data[14]

    struct in_addr:
        unsigned long s_addr

    struct sockaddr_in:
        unsigned short sin_family
        unsigned short sin_port
        in_addr sin_addr
        char sin_zero[8]

cdef extern from "<pcap/pcap.h>":
    enum:
        PCAP_ERRBUF_SIZE

    enum:
        PCAP_CHAR_ENC_LOCAL
        PCAP_CHAR_ENC_UTF_8

    ctypedef unsigned int bpf_u_int32

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

    int pcap_init(unsigned int, char*)

    int	pcap_findalldevs(pcap_if_t **, char *)

    void pcap_freealldevs(pcap_if_t *)

    const char* pcap_lib_version()
