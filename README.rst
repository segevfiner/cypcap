cypcap
======
.. image:: https://img.shields.io/pypi/v/cypcap.svg
   :target: https://pypi.org/project/cypcap/
   :alt: PyPI

.. image:: https://github.com/segevfiner/cypcap/actions/workflows/docs.yml/badge.svg
   :target: https://segevfiner.github.io/cypcap/
   :alt: Docs

.. image:: https://github.com/segevfiner/cypcap/actions/workflows/build-and-test.yml/badge.svg
   :target: https://github.com/segevfiner/cypcap/actions/workflows/build-and-test.yml
   :alt: Build & Test

This package is a Cython based binding for modern libpcap versions, for Python 3.6+, attempting to
be more complete than existing and poorly maintained packages.

`Documentation <https://segevfiner.github.io/cypcap/>`_

Installation
------------
::

    $ pip install cypcap

Python 3.6+ and libpcap 1.8+ is required (Older libpcap versions can be supported if needed).

Build From Source
^^^^^^^^^^^^^^^^^
On Windows, download and extract the `Npcap SDK`_ and set the enviromnet variable ``NPCAP_SDK`` to
its location (You will also need to install Npcap, Wireshark installs it as part of its
installation).

On Linux, install the libpcap development package from your package manager. e.g. For Ubuntu::

    $ sudo apt update && sudo apt install libpcap-dev

.. _`Npcap SDK`: https://nmap.org/npcap/

Quickstart
----------
.. code-block:: python

    import cypcap

    dev = cypcap.findalldevs()[0]  # You should filter the list or let the user choose a device
    with cypcap.create(dev) as pcap:
        pcap.set_snaplen(65536)
        pcap.set_promisc(True)
        pcap.set_timeout(1000)
        pcap.activate()

        for pkthdr, data in pcap:
            if pkthdr is None:
                continue

            print(pkthdr, data)

License
-------
3-Clause BSD license (The same kind of license that libpcap uses).
