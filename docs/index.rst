Welcome to cypcap's documentation!
==================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

This package is a Cython based binding for modern libpcap versions, attempting to be more complete
than existing and poorly maintained implementations.

Check `pcap(3pcap) <https://www.tcpdump.org/manpages/pcap.3pcap.html>`_ for detailed documentation
about libpcap.

.. module:: cypcap

Finding Devices
---------------
.. autofunction:: findalldevs

.. autoclass:: PcapIf()
   :members:

.. autoclass:: PcapAddr()
   :members:

.. autoclass:: PcapIfFlags
   :members:
   :undoc-members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
