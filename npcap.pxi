from cpython cimport PyErr_SetFromWindowsErr
cimport cpcap

cdef extern from "<Windows.h>":
    # TODO Using Py_UNICODE raises a warning, is there anything better?
    ctypedef Py_UNICODE WCHAR
    ctypedef WCHAR* LPWSTR
    ctypedef const WCHAR* LPCWSTR
    ctypedef unsigned int UINT
    ctypedef bint BOOL

    enum:
        MAX_PATH

    UINT GetSystemDirectoryW(LPWSTR, UINT)
    BOOL SetDllDirectoryW(LPCWSTR)

cdef int load_npcap_dlls() except -1:
    cdef WCHAR system_dir[MAX_PATH]
    cdef UINT length = GetSystemDirectoryW(system_dir, MAX_PATH)
    if not length:
        PyErr_SetFromWindowsErr(0)

    npcap_dir = system_dir[:length] + "\\Npcap"

    if not SetDllDirectoryW(npcap_dir):
        PyErr_SetFromWindowsErr(0)

    cpcap.pcap_lib_version()

    if not SetDllDirectoryW(NULL):
        PyErr_SetFromWindowsErr(0)

load_npcap_dlls()
