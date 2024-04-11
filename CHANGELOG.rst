Changelog
=========

Unreleased
----------
Added
^^^^^
* ``Dumper.flush``.

v0.5.0 (2023-10-14)
-------------------
Added
^^^^^
* Python 3.12 wheels.

Changed
^^^^^^^
* Now using Cython 3.

v0.4.2 (2022-11-04)
-------------------

Added
^^^^^
* Python 3.11 wheels.

Fixed
^^^^^
* A `const` compiler warning.

v0.4.1 (2022-02-09)
-------------------

Fixed
^^^^^
* ``dumps(..., cypcap.BpfDumpType.C_ARRAY)`` outputted wrong syntax.

v0.4.0 (2022-01-14)
-------------------

Added
^^^^^
* ``BpfProgram`` now has ``__getitem__``, ``__len__``, ``__init__``, ``__iter__``, and can be turned
  into a list.
* ``dumps`` can now dump the formats that ``debug_dump`` used to output and return them as a string
  instead of printing to stdout.
* Platform specific functions ``Pcap.set_protocol_linux``, ``Pcap.get_selectable_fd``,
  ``Pcap.get_required_select_timeout``, and ``Pcap.getevent``.
* ``cypcap.bpf`` module with constants and utility functions for manually written BPF.

Changed
^^^^^^^
* Classes which should not be instantiated from Python directly should now raise
  (``Pcap`` & ``Dumper``).
* ``cypcap`` is now a package rather than a single file module, API remains the same.

Removed
^^^^^^^
* ``debug_dump`` is merged into ``dumps`` by a new type parameter.

Fixed
^^^^^
* ``set_config``, ``set_pre_config`` had wrong typing. (Although those are not exported to an
  interface file yet).

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
