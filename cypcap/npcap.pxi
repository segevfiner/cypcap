from . cimport cpcap

cdef extern from *:
    """
    #ifdef _WIN32
    #include <Windows.h>
    #include <delayimp.h>
    #include <stdio.h>
    #include <wchar.h>
    static int load_npcap_dlls(void)
    {
        WCHAR npcap_dir[512];
        UINT len;
        len = GetSystemDirectoryW(npcap_dir, 480);
        if (!len) {
            PyErr_SetFromWindowsErr(0);
            return -1;
        }

        wcscat_s(npcap_dir, 512, L"\\\\Npcap");
        if (SetDllDirectoryW(npcap_dir) == 0) {
            PyErr_SetFromWindowsErr(0);
            return -1;
        }

        __try {
            pcap_lib_version();
        } __except (GetExceptionCode() == VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)) {
            PyErr_SetString(PyExc_ImportError, "Failed to load Npcap (Is it installed?)");
            return -1;
        }

        if (SetDllDirectoryW(NULL) == 0) {
            PyErr_SetFromWindowsErr(0);
            return -1;
        }

        return 0;
    }
    #else
    static int load_npcap_dlls(void)
    {
        return 0;
    }
    #endif
    """

    int load_npcap_dlls() except -1


load_npcap_dlls()
