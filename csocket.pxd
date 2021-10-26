cdef extern from * nogil:
    """
    #ifdef _WIN32
    #include <WinSock2.h>
    #include <WS2tcpip.h>
    #else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #endif
    """
    ctypedef int socklen_t

    enum:
        AF_INET
        AF_INET6

    enum:
        INET_ADDRSTRLEN
        INET6_ADDRSTRLEN

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

    struct in6_addr:
        unsigned char s6_addr[16]

    struct sockaddr_in6:
        unsigned short sin6_family
        unsigned short sin6_port
        unsigned long sin6_flowinfo
        in6_addr sin6_addr
        unsigned long sin6_scope_id

    const char *inet_ntop(int af, const void* src,
                          char* dst, socklen_t size)

    struct timeval:
        long tv_sec
        long tv_usec
