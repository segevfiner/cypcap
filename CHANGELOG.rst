Changelog
=========

v0.3.0 (2021-11-16)
-------------------

Changed
^^^^^^^
* The ``optimize`` parameter to ``Pcap.compile`` now defaults to ``True``.
* Can now call ``Pcap.setfilter`` with a ``str`` which will be compiled by calling ``Pcap.compile``.

v0.2.0 (2021-11-15)
-------------------

Added
^^^^^
* Wheels for Windows, Linux & macOS.
* ``Pkthdr`` can be created from Python and is mutable (Useful for ``bpf.offline_filter``).
* Add ``BpfProgram.dumps``/``BpfProgram.loads`` to dump and load the filter in the format used by
  iptables, tc-bpf, etc.
* ``Pcap`` now has a ``__repr__``.
* ``Pcap`` now has a ``type`` and ``source`` attributes.
* Add ``PcapType`` for indicating the type of a ``Pcap``.
* ``Pkthdr.ts_datetime`` & ``Pkthdr.ts_utcdatetime`` that return ``Pkthdr.ts`` as a naive
  ``datetime``.
* ``Pcap.set_pre_config`` & ``Pcap.set_config`` shortcuts to set ``Pcap`` configuration via keyword
  arguments.

Changed
^^^^^^^
* Change ``findalldevs`` interface address parsing to use the same format as the ``socket``
  module and add support for ``AF_PACKET`` ``sockaddr_ll`` used in Linux.
* Addresses in ``PcapIf.addresses``/``PcapAddr`` will now be in the format
  ``Tuple[socket.AddressFamily, <sockaddr tuple>]``.
* ``BpfProgram.dump`` renamed to ``BpfProgram.debug_dump``.
* ``set_timeout`` & ``open_live`` now accept Python style float seconds instead of milliseconds.
* The ``netmask`` argument to ``Pcap.compile`` is now optional, the package will try to figure out
  the correct value by itself.

v0.1.1 (2021-11-03)
-------------------

Fixed
^^^^^
* ``cypcap.pyx`` was missing from sdist due to ``cythonize``. (Bug in Cython?)

v0.1.0 (2021-11-03)
-------------------

Added
^^^^^
* Tests & Github Actions CI

Changed
^^^^^^^
* Support ``os.PathLike`` in ``dump_open`` & ``dump_open_append``.
* Support ``os.PathLike`` in ``open_offline``.
* ``inject`` and ``sendpacket`` now take an object implementing the buffer protocol.
* Switch to using ``cythonize`` in ``setup.py`` (The built-in setuptools integration uses the
  deprecated ``old_build_ext`` and keyed off whether to generate C sources on whether Cython is
  installed).

Fixed
^^^^^
* ``NETMASK_UNKNOWN`` was of the wrong type.

v0.1.0b1 (2021-10-26)
---------------------
Initial beta release. Only tested manually and lightly.
