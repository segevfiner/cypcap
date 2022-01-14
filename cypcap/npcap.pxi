from . cimport cpcap

cdef extern from *:
    """
    #ifdef _WIN32
    #include <Windows.h>
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

        pcap_lib_version();

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
