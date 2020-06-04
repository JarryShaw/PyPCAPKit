Extractor for PCAP Files
========================

:mod:`pcapkit.foundation.extraction` contains
:class:`~pcapkit.foundation.extraction.Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
extracts parametres from a PCAP file.

.. todo::

   Implement engine support for |pypcap|_ & |pycapfile|_.

.. automodule:: pcapkit.foundation.extraction
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. |pypcap| replace:: ``pypcap``
.. _pypcap: https://pypcap.readthedocs.io/en/latest/
.. |pycapfile| replace:: ``pycapfile``
.. _pycapfile: https://github.com/kisom/pypcapfile
