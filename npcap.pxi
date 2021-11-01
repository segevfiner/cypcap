cimport cpcap

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
            fprintf(stderr, "Error in GetSystemDirectory: %x\\n", GetLastError());
            return 0;
        }
        wcscat_s(npcap_dir, 512, L"\\\\Npcap");
        if (SetDllDirectoryW(npcap_dir) == 0) {
            fprintf(stderr, "Error in SetDllDirectory: %x\\n", GetLastError());
            return 0;
        }
        pcap_lib_version();
        if (SetDllDirectoryW(NULL) == 0) {
            fprintf(stderr, "Error in SetDllDirectory: %x\\n", GetLastError());
            return 0;
        }
        return 1;
    }
    #else
    static int load_npcap_dlls(void)
    {
        return 1;
    }
    #endif
    """
    int load_npcap_dlls()


load_npcap_dlls()
