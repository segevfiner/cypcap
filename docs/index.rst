Welcome to cypcap's documentation!
==================================

Version: |release|

This package is a Cython based binding for modern libpcap versions, for Python 3.6+, attempting to
be more complete than existing and poorly maintained packages.

See `pcap(3pcap) <https://www.tcpdump.org/manpages/pcap.3pcap.html>`_ for more detailed
documentation about libpcap.

See the `README.rst <https://github.com/segevfiner/cypcap/blob/master/README.rst>`_ for installation instructions.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   bpf
   changelog

.. module:: cypcap

Finding Devices/Interfaces
--------------------------
.. autofunction:: findalldevs

.. autoclass:: PcapIf()
   :members:

.. autoclass:: PcapAddr()
   :members:

.. autoclass:: PcapIfFlags
   :members:
   :undoc-members:
   :member-order: bysource

.. autofunction:: lookupnet

Opening a Pcap
--------------
.. autofunction:: create

.. autofunction:: open_live

.. autofunction:: open_dead(linktype: DatalinkType, snaplen: int, precision: TstampPrecision=TstampPrecision.MICRO) -> cypcap.Pcap

.. autofunction:: open_offline

.. autofunction:: compile

Pcap
----
.. autoclass:: Pcap
   :members:
   :undoc-members:
   :exclude-members: type, source

   .. attribute:: type
      :type: PcapType

      Type of Pcap.

   .. attribute:: source
      :type: str

      Source of the Pcap, meaning depends on :attr:`type`.

.. autoclass:: PcapType
   :members:
   :undoc-members:
   :member-order: bysource

.. autoclass:: Pkthdr(ts: float=0.0, caplen: int=0, len: int=0)
   :members:
   :undoc-members:

BpfProgram
----------
.. autoclass:: BpfProgram
   :members:
   :undoc-members:

Stat
----
.. autoclass:: Stat
   :members:
   :undoc-members:

Dumper
------
.. autoclass:: Dumper
   :members:
   :undoc-members:

Enumeration & Constants
-----------------------
.. autoclass:: DatalinkType
   :members:
   :undoc-members:
   :member-order: bysource

.. autoclass:: Direction
   :members:
   :undoc-members:
   :member-order: bysource

.. autoclass:: TstampType
   :members:
   :undoc-members:
   :member-order: bysource

.. autoclass:: TstampPrecision
   :members:
   :undoc-members:
   :member-order: bysource

.. data:: NETMASK_UNKNOWN

   The netmask for :meth:`compile` is unknown.

Getting library version
-----------------------
.. autofunction:: lib_version

Errors & Warnings
-----------------
.. autoclass:: Error

.. autoclass:: Warning

.. autoclass:: ErrorCode
   :members:
   :undoc-members:
   :member-order: bysource

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
