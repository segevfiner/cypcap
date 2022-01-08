from .csocket cimport sockaddr, timeval
from libc.stdint cimport int64_t

cdef extern from "<pcap/pcap.h>" nogil:
    """
    #include <stdio.h>

    // Definitions and stubs for supporting older libpcap versions
    #ifndef PCAP_CHAR_ENC_LOCAL
    #define PCAP_CHAR_ENC_LOCAL	0x00000000U
    #endif

    #ifndef PCAP_CHAR_ENC_UTF_8
    #define PCAP_CHAR_ENC_UTF_8	0x00000001U
    #endif

    #ifndef PCAP_TSTAMP_HOST_HIPREC_UNSYNCED
    #define PCAP_TSTAMP_HOST_HIPREC_UNSYNCED 5
    #endif

    #ifndef PCAP_IF_WIRELESS
    #define PCAP_IF_WIRELESS 0x00000008
    #endif

    #ifndef PCAP_IF_CONNECTION_STATUS
    #define PCAP_IF_CONNECTION_STATUS 0x00000030
    #endif

    #ifndef PCAP_IF_CONNECTION_STATUS_UNKNOWN
    #define PCAP_IF_CONNECTION_STATUS_UNKNOWN 0x00000000
    #endif

    #ifndef PCAP_IF_CONNECTION_STATUS_CONNECTED
    #define PCAP_IF_CONNECTION_STATUS_CONNECTED 0x00000010
    #endif

    #ifndef PCAP_IF_CONNECTION_STATUS_DISCONNECTED
    #define PCAP_IF_CONNECTION_STATUS_DISCONNECTED 0x00000020
    #endif

    #ifndef PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE
    #define PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE 0x00000030
    #endif

    #ifndef HAVE_PCAP_INIT
    static int pcap_init(unsigned int opts, char *errbuf)
    {
        return 0;
    }
    #endif

    #ifndef HAVE_DATALINK_VAL_TO_DESCRIPTION_OR_DLT
    static const char * pcap_datalink_val_to_description_or_dlt(int dlt)
    {
            static char unkbuf[40];
            const char *description;

            description = pcap_datalink_val_to_description(dlt);
            if (description != NULL) {
                    return description;
            } else {
                    (void)snprintf(unkbuf, sizeof(unkbuf), "DLT %u", dlt);
                    return unkbuf;
            }
    }
    #endif

    #ifndef _WIN32
    static void *pcap_getevent(pcap_t *p)
    {
        return 0;
    }
    #endif

    #ifndef __linux__
    static int pcap_set_protocol_linux(pcap_t *p, int protocol)
    {
        return PCAP_ERROR;
    }
    #endif

    #if defined(_WIN32) || defined(MSDOS)
    static int pcap_get_selectable_fd(pcap_t *p)
    {
        return -1;
    }

    static struct timeval *pcap_get_required_select_timeout(pcap_t *p)
    {
        return NULL;
    }
    #endif
    """

    ctypedef unsigned int bpf_u_int32

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

        DLT_RAW

        DLT_IEEE802_11_RADIO

        DLT_DOCSIS

    struct bpf_insn:
        unsigned short	code
        unsigned char 	jt
        unsigned char 	jf
        bpf_u_int32     k

    struct bpf_program:
        unsigned int bf_len
        bpf_insn* bf_insns

    enum:
        PCAP_ERRBUF_SIZE

    enum:
        PCAP_CHAR_ENC_LOCAL
        PCAP_CHAR_ENC_UTF_8

    struct pcap:
        pass

    ctypedef pcap pcap_t

    struct pcap_dumper:
        pass

    ctypedef pcap_dumper pcap_dumper_t

    ctypedef enum pcap_direction_t:
        PCAP_D_INOUT
        PCAP_D_IN
        PCAP_D_OUT

    struct pcap_pkthdr:
        timeval ts
        bpf_u_int32 caplen
        bpf_u_int32 len

    struct pcap_stat:
        unsigned int ps_recv
        unsigned int ps_drop
        unsigned int ps_ifdrop

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

    ctypedef void (*pcap_handler)(unsigned char *, const pcap_pkthdr *, const unsigned char *) except *

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

    enum: PCAP_NETMASK_UNKNOWN

    int pcap_init(unsigned int, char *)

    int pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *)

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

    int pcap_set_protocol_linux(pcap_t *, int)  # Linux only

    pcap_t *pcap_open_live(const char *, int, bint, int, char *)

    pcap_t *pcap_open_dead(int, int)

    pcap_t *pcap_open_dead_with_tstamp_precision(int, int, unsigned int)

    pcap_t *pcap_open_offline_with_tstamp_precision(const char *, unsigned int, char *)

    pcap_t *pcap_open_offline(const char *, char *)

    void pcap_close(pcap_t *)

    int pcap_loop(pcap_t *, int, pcap_handler, unsigned char *) except *

    int pcap_dispatch(pcap_t *, int, pcap_handler, unsigned char *) except *

    const unsigned char *pcap_next(pcap_t *, pcap_pkthdr *)

    int pcap_next_ex(pcap_t *, pcap_pkthdr **, const unsigned char **)

    void pcap_breakloop(pcap_t *)

    int pcap_stats(pcap_t *, pcap_stat *)

    int pcap_setfilter(pcap_t *, bpf_program *)

    int pcap_setdirection(pcap_t *, pcap_direction_t);

    int pcap_getnonblock(pcap_t *, char *)

    int pcap_setnonblock(pcap_t *, bint, char *)

    int pcap_inject(pcap_t *, const void *, size_t)

    int pcap_sendpacket(pcap_t *, const unsigned char *, int)

    const char *pcap_statustostr(int)

    char* pcap_geterr(pcap_t *)

    int	pcap_compile(pcap_t *, bpf_program *, const char *, int, bpf_u_int32)

    void pcap_freecode(bpf_program *)

    bint pcap_offline_filter(const bpf_program *, const pcap_pkthdr *, const unsigned char *)

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

    pcap_dumper_t *pcap_dump_open(pcap_t *, const char *)

    pcap_dumper_t *pcap_dump_open_append(pcap_t *, const char *)

    long pcap_dump_ftell(pcap_dumper_t *)

    int64_t pcap_dump_ftell64(pcap_dumper_t *)

    int pcap_dump_flush(pcap_dumper_t *)

    void pcap_dump_close(pcap_dumper_t *)

    void pcap_dump(unsigned char *, const pcap_pkthdr *, const unsigned char *)

    int pcap_findalldevs(pcap_if_t **, char *)

    void pcap_freealldevs(pcap_if_t *)

    const char *pcap_lib_version()

    void bpf_dump(const bpf_program *, int)

    char *bpf_image(const bpf_insn *, int)

    # Windows only
    void *pcap_getevent(pcap_t *p)

    # UN*X only
    int	pcap_get_selectable_fd(pcap_t *)
    timeval *pcap_get_required_select_timeout(pcap_t *)
