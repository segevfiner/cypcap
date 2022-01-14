cdef extern from * nogil:
    """
    #ifdef _WIN32
    #include <WinSock2.h>
    #else
    #include <sys/socket.h>
    #endif
    """

    struct sockaddr:
        unsigned short sa_family
        char sa_data[14]

    struct timeval:
        long tv_sec
        long tv_usec
