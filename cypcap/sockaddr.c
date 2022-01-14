// This is based on Python's own socketmodule.c (See LICENSE-PSF)

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pyconfig.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_NETPACKET_PACKET_H
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#endif

static PyObject *
make_ipv4_addr(const struct sockaddr_in *addr)
{
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf)) == NULL) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    return PyUnicode_FromString(buf);
}

static PyObject *
make_ipv6_addr(const struct sockaddr_in6 *addr)
{
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &addr->sin6_addr, buf, sizeof(buf)) == NULL) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    return PyUnicode_FromString(buf);
}

PyObject *
makesockaddr_c(struct sockaddr *addr)
{
    if (addr == NULL) {
        /* No address */
        Py_RETURN_NONE;
    }

    switch (addr->sa_family) {

    case AF_INET:
    {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        PyObject *addrobj = make_ipv4_addr(a);
        PyObject *ret = NULL;
        if (addrobj) {
            ret = Py_BuildValue("Oi", addrobj, ntohs(a->sin_port));
            Py_DECREF(addrobj);
        }
        return ret;
    }

 case AF_INET6:
    {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        PyObject *addrobj = make_ipv6_addr(a);
        PyObject *ret = NULL;
        if (addrobj) {
            ret = Py_BuildValue("OiII",
                                addrobj,
                                ntohs(a->sin6_port),
                                ntohl(a->sin6_flowinfo),
                                a->sin6_scope_id);
            Py_DECREF(addrobj);
        }
        return ret;
    }

#if defined(HAVE_NETPACKET_PACKET_H) && defined(SIOCGIFNAME)
    case AF_PACKET:
    {
        int sockfd = socket(AF_PACKET, SOCK_RAW, 0);
        struct sockaddr_ll *a = (struct sockaddr_ll *)addr;
        const char *ifname = "";
        struct ifreq ifr;
        /* need to look up interface name give index */
        if (a->sll_ifindex) {
            ifr.ifr_ifindex = a->sll_ifindex;
            if (ioctl(sockfd, SIOCGIFNAME, &ifr) == 0)
                ifname = ifr.ifr_name;
        }
        close(sockfd);
        return Py_BuildValue("shbhy#",
                             ifname,
                             ntohs(a->sll_protocol),
                             a->sll_pkttype,
                             a->sll_hatype,
                             a->sll_addr,
                             (Py_ssize_t)a->sll_halen);
    }
#endif /* HAVE_NETPACKET_PACKET_H && SIOCGIFNAME */

default:
        /* If we don't know the address family, don't raise an
           exception -- return it as an (int, bytes) tuple. */
        return Py_BuildValue("iy#",
                             addr->sa_family,
                             addr->sa_data,
                             sizeof(addr->sa_data));

    }
}
