from csocket cimport sockaddr, timeval

cdef extern from "<pcap/pcap.h>" nogil:
    enum:
        DLT_NULL
        DLT_EN10MB
        DLT_EN3MB
        DLT_AX25
        DLT_PRONET
        DLT_CHAOS
        DLT_IEEE802
        DLT_ARCNET
        DLT_SLIP
        DLT_PPP
        DLT_FDDI

    enum:
        PCAP_ERRBUF_SIZE

    enum:
        PCAP_CHAR_ENC_LOCAL
        PCAP_CHAR_ENC_UTF_8

    ctypedef unsigned int bpf_u_int32

    struct pcap:
        pass

    ctypedef pcap pcap_t

    struct pcap_pkthdr:
        timeval ts
        bpf_u_int32 caplen
        bpf_u_int32 len

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

    enum:
        PCAP_ERROR
        PCAP_ERROR_BREAK
        PCAP_ERROR_NOT_ACTIVATED
        PCAP_ERROR_ACTIVATED
        PCAP_ERROR_NO_SUCH_DEVICE
        PCAP_ERROR_RFMON_NOTSUP
        PCAP_ERROR_NOT_RFMON
        PCAP_ERROR_PERM_DENIED
        PCAP_ERROR_IFACE_NOT_UP
        PCAP_ERROR_CANTSET_TSTAMP_TYPE
        PCAP_ERROR_PROMISC_PERM_DENIED
        PCAP_ERROR_TSTAMP_PRECISION_NOTSUP

    enum:
        PCAP_WARNING
        PCAP_WARNING_PROMISC_NOTSUP
        PCAP_WARNING_TSTAMP_TYPE_NOTSUP

    int pcap_init(unsigned int, char *)

    pcap_t *pcap_create(const char *, char *)

    int pcap_set_snaplen(pcap_t *, int)

    int pcap_set_promisc(pcap_t *, bint)

    int pcap_can_set_rfmon(pcap_t *)

    int pcap_set_rfmon(pcap_t *, bint)

    int pcap_set_timeout(pcap_t *, int)

    int pcap_set_tstamp_type(pcap_t *, int)

    int pcap_set_immediate_mode(pcap_t *, bint)

    int pcap_set_buffer_size(pcap_t *, int)

    int pcap_set_tstamp_precision(pcap_t *, int)

    int pcap_get_tstamp_precision(pcap_t *)

    int pcap_activate(pcap_t *)

    int pcap_list_tstamp_types(pcap_t *, int **)

    void pcap_free_tstamp_types(int *)

    int pcap_tstamp_type_name_to_val(const char *)

    const char *pcap_tstamp_type_val_to_name(int)

    const char *pcap_tstamp_type_val_to_description(int)

    enum:
        PCAP_TSTAMP_HOST
        PCAP_TSTAMP_HOST_LOWPREC
        PCAP_TSTAMP_HOST_HIPREC
        PCAP_TSTAMP_ADAPTER
        PCAP_TSTAMP_ADAPTER_UNSYNCED
        PCAP_TSTAMP_HOST_HIPREC_UNSYNCED

    enum:
        PCAP_TSTAMP_PRECISION_MICRO
        PCAP_TSTAMP_PRECISION_NANO

    pcap_t *pcap_open_live(const char *, int, bint, int, char *)

    pcap_t *pcap_open_dead(int, int)

    pcap_t *pcap_open_dead_with_tstamp_precision(int, int, unsigned int)

    pcap_t *pcap_open_offline_with_tstamp_precision(const char *, unsigned int, char *)

    pcap_t *pcap_open_offline(const char *, char *)

    void pcap_close(pcap_t *)

    const unsigned char *pcap_next(pcap_t *, pcap_pkthdr *)

    int pcap_next_ex(pcap_t *, pcap_pkthdr **, const unsigned char **);

    const char *pcap_statustostr(int)

    char* pcap_geterr(pcap_t *)

    int pcap_datalink(pcap_t *)

    int pcap_list_datalinks(pcap_t *, int **)

    int pcap_set_datalink(pcap_t *, int)

    void pcap_free_datalinks(int *)

    int pcap_datalink_name_to_val(const char *)

    const char *pcap_datalink_val_to_name(int)

    const char *pcap_datalink_val_to_description(int)

    const char *pcap_datalink_val_to_description_or_dlt(int)

    int	pcap_snapshot(pcap_t *)

    bint pcap_is_swapped(pcap_t *)

    int pcap_major_version(pcap_t *)

    int pcap_minor_version(pcap_t *)

    int pcap_findalldevs(pcap_if_t **, char *)

    void pcap_freealldevs(pcap_if_t *)

    const char *pcap_lib_version()
