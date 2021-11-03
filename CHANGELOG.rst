Changelog
=========

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
