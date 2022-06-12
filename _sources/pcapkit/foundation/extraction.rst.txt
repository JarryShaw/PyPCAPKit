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
   :no-members:
   :show-inheritance:
   :no-special-members: __init__

   .. autoattribute:: __output__
      :no-value:

   .. autoproperty:: info
   .. autoproperty:: length
   .. autoproperty:: format
   .. autoproperty:: input
   .. autoproperty:: output
   .. autoproperty:: header
   .. autoproperty:: frame
   .. autoproperty:: reassembly
   .. autoproperty:: trace
   .. autoproperty:: engine

   .. automethod:: run
   .. automethod:: record_header
   .. automethod:: record_frames

   .. automethod:: register
   .. automethod:: make_name

   .. automethod:: _read_frame
   .. automethod:: _cleanup

   .. automethod:: _default_read_frame
   .. automethod:: _run_scapy
   .. automethod:: _scapy_read_frame
   .. automethod:: _run_dpkt
   .. automethod:: _dpkt_read_frame
   .. automethod:: _run_pyshark
   .. automethod:: _pyshark_read_frame

   .. automethod:: __iter__
   .. automethod:: __next__
   .. automethod:: __call__

   .. autoattribute:: _flag_a
   .. autoattribute:: _flag_d
   .. autoattribute:: _flag_e
   .. .. autoattribute:: _flag_f
   .. autoattribute:: _flag_q
   .. autoattribute:: _flag_t
   .. .. autoattribute:: _flag_v

   .. autoattribute:: _exptl
   .. autoattribute:: _exlyr
   .. autoattribute:: _exeng
   .. autoattribute:: _expkg
   .. autoattribute:: _extmp

   .. autoattribute:: _gbhdr
   .. .. autoattribute:: _vinfo
   .. .. autoattribute:: _dlink
   .. .. autoattribute:: _nnsec
   .. .. autoattribute:: _type

Data Structures
---------------

.. autoclass:: pcapkit.foundation.extraction.ReassemblyData
   :show-inheritance:
   :no-special-members: __init__

   :param ipv4: IPv4 reassembly data.
   :param ipv6: IPv6 reassembly data.
   :param tcp: TCP reassembly data.

   .. autoattribute:: ipv4
   .. autoattribute:: ipv6
   .. autoattribute:: tcp

.. |pypcap| replace:: ``pypcap``
.. _pypcap: https://pypcap.readthedocs.io/en/latest/
.. |pycapfile| replace:: ``pycapfile``
.. _pycapfile: https://github.com/kisom/pypcapfile
