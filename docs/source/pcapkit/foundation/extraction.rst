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

   :param fin: file name to be read; if file not exist, raise :exc:`FileNotFound`
   :param fout: file name to be written
   :param format: file format of output

   :param auto: if automatically run till EOF
   :param extension: if check and append extensions to output file
   :param store: if store extracted packet info

   :param files: if split each frame into different files
   :param nofile: if no output file is to be dumped
   :param verbose: a :obj:`bool` value or a function takes the :class:`Extractor` instance and current parsed frame (depends on engine selected) as parameters to print verbose output information

   :param engine: extraction engine to be used
   :param layer: extract til which layer
   :param protocol: extract til which protocol

   :param reassembly: if perform reassembly
   :param strict: if set strict flag for reassembly

   :param trace: if trace TCP traffic flows
   :param trace_fout: path name for flow tracer if necessary
   :param trace_format: output file format of flow tracer
   :param trace_byteorder: output file byte order
   :param trace_nanosecond: output nanosecond-resolution file flag

   :param ip: if record data for IPv4 & IPv6 reassembly
   :param ipv4: if perform IPv4 reassembly
   :param ipv6: if perform IPv6 reassembly
   :param tcp: if perform TCP reassembly and/or flow tracing

   .. autoproperty:: length
   .. autoproperty:: format
   .. autoproperty:: input
   .. autoproperty:: output
   .. autoproperty:: frame
   .. autoproperty:: reassembly
   .. autoproperty:: trace
   .. autoproperty:: engine

   .. automethod:: register_dumper
   .. automethod:: register_engine

   .. automethod:: run
   .. automethod:: record_header
   .. automethod:: record_frames

   .. autoattribute:: _frnum
   .. autoattribute:: _reasm
   .. autoattribute:: _trace

   .. autoattribute:: _ifile
   .. autoattribute:: _ofile

   .. autoattribute:: _exnam
   .. autoattribute:: _exeng

   .. autoattribute:: _flag_a
   .. autoattribute:: _flag_d
   .. autoattribute:: _flag_e
   .. autoattribute:: _flag_q
   .. autoattribute:: _flag_t
   .. autoattribute:: _flag_v

   .. autoattribute:: _ipv4
   .. autoattribute:: _ipv6
   .. autoattribute:: _tcp

   .. autoattribute:: __output__
      :no-value:
   .. autoattribute:: __engine__
      :no-value:

   .. automethod:: __iter__
   .. automethod:: __next__
   .. automethod:: __call__

.. |pypcap| replace:: ``pypcap``
.. _pypcap: https://pypcap.readthedocs.io/en/latest/
.. |pycapfile| replace:: ``pycapfile``
.. _pycapfile: https://github.com/kisom/pypcapfile
