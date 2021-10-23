cdef extern from "<pcap/pcap.h>":
    enum:
        PCAP_ERRBUF_SIZE

    enum:
        PCAP_CHAR_ENC_LOCAL
        PCAP_CHAR_ENC_UTF_8

    int pcap_init(unsigned int, char*)

    const char* pcap_lib_version()
