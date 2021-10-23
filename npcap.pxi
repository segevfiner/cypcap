from cpython cimport PyErr_SetFromWindowsErr
cimport cpcap

cdef extern from "<Windows.h>":
    ctypedef Py_UNICODE WCHAR
    ctypedef WCHAR* LPWSTR
    ctypedef const WCHAR* LPCWSTR
    ctypedef unsigned int UINT
    ctypedef bint BOOL

    enum:
        MAX_PATH

    UINT GetSystemDirectoryW(LPWSTR, UINT)
    BOOL SetDllDirectoryW(LPCWSTR)

def load_npcap_dlls():
    cdef WCHAR system_dir[MAX_PATH]
    cdef UINT length = GetSystemDirectoryW(system_dir, MAX_PATH)
    if not length:
        PyErr_SetFromWindowsErr(0)
        raise

    npcap_dir = system_dir[:length] + "\\Npcap"

    if not SetDllDirectoryW(npcap_dir):
        PyErr_SetFromWindowsErr(0)
        raise

    cpcap.pcap_lib_version()

    if not SetDllDirectoryW(NULL):
        PyErr_SetFromWindowsErr(0)
        raise

load_npcap_dlls()
