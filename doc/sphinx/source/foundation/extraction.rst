Extractor for PCAP Files
========================

.. module:: pcapkit.foundation.extraction

:mod:`pcapkit.foundation.extraction` contains
:class:`~pcapkit.foundation.extraction.Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
extracts parametres from a PCAP file.

.. todo::

   Implement engine support for |pypcap|_ & |pycapfile|_.

.. autoclass:: pcapkit.foundation.extraction.Extractor
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. attribute:: _ifnm
      :type: str

      Input file name.

   .. attribute:: _ofnm
      :type: str

      Output file name.

   .. attribute:: _fext
      :type: str

      Output file extension.

   .. attribute:: _flag_a
      :type: bool

      Auto extraction flag (as the ``auto`` parameter).

   .. attribute:: _flag_d
      :type: bool

      Data storing flag (as the ``store`` parameter).

   .. attribute:: _flag_e
      :type: bool

      EOF flag.

   .. attribute:: _flag_f
      :type: bool

      Split output into files flag (as the ``files`` parameter).

   .. attribute:: _flag_m
      :type: bool

      Multiprocessing engine flag.

   .. attribute:: _flag_q
      :type: bool

      No output flag (as the ``nofile`` parameter).

   .. attribute:: _flag_t
      :type: bool

      TCP flow tracing flag (as the ``trace`` parameter).

   .. attribute:: _flag_v
      :type: bool

      Verbose output flag (as the ``verbose`` parameter).

.. data:: pcapkit.foundation.extraction.CPU_CNT
   :type: int

   Number of available CPUs. The value is used as the maximum
   concurrent workers in multiprocessing engines.

.. autodata:: pcapkit.foundation.extraction.LAYER_LIST
.. autodata:: pcapkit.foundation.extraction.PROTO_LIST

.. |pypcap| replace:: ``pypcap``
.. _pypcap: https://pypcap.readthedocs.io/en/latest/
.. |pycapfile| replace:: ``pycapfile``
.. _pycapfile: https://github.com/kisom/pypcapfile
