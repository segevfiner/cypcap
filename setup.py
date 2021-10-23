import sys
import os
from setuptools import setup, Extension


if sys.platform == "win32":
    try:
        npcap_sdk = os.environ["NPCAP_SDK"]
    except KeyError:
        # TODO Better message
        print("Please define NPCAP_SDK", file=sys.stderr)
        sys.exit(1)

    include_dirs = [os.path.join(npcap_sdk, "Include")]
    if sys.maxsize > 2**32:
        library_dirs = [os.path.join(npcap_sdk, R"Lib\x64")]
    else:
        library_dirs = [os.path.join(npcap_sdk, "Lib")]
    libraries = ["delayimp", "wpcap"]
    extra_link_args = ["/DELAYLOAD:wpcap.dll"]
else:
    include_dirs = []
    library_dirs = []
    libraries = ["pcap"]
    extra_link_args = []


setup(
    name="cypcap",
    version="0.1.0",
    ext_modules=[
        Extension(
            "cypcap", ["cypcap.pyx"],
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries,
            extra_link_args=extra_link_args,
            depends=["cpcap.pxd", "npcap.pxi"],
        ),
    ]
)
