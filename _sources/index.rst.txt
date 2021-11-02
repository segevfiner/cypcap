Welcome to cypcap's documentation!
==================================

.. toctree::
   :hidden:
   :maxdepth: 2

   changelog

Version: |release|

This package is a Cython based binding for modern libpcap versions, for Python 3.6+, attempting to
be more complete than existing and poorly maintained packages.

See `pcap(3pcap) <https://www.tcpdump.org/manpages/pcap.3pcap.html>`_ for more detailed
documentation about libpcap.

See the `README.rst <https://github.com/segevfiner/cypcap/blob/master/README.rst>`_ for installation instructions.

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

.. autoclass:: Pkthdr
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
