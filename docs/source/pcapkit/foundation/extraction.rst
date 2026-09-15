File Extractor
==============

.. module:: pcapkit.foundation.extraction

:mod:`pcapkit.foundation.extraction` contains
:class:`~pcapkit.foundation.extraction.Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
extracts parametres from a PCAP file.

.. seealso::

   Engine support for |pypcap|_ and |pypcapfile|_ has since landed, as
   :class:`pcapkit.foundation.engines.pypcap.PyPCAP` (``engine='pypcap'``) and
   :class:`pcapkit.foundation.engines.pypcapfile.PyPCAPFile`
   (``engine='pypcapfile'``). Both support less than the ``default`` engine
   does; :doc:`engines/index` tabulates the gaps, and :doc:`../../index`
   documents the installation prerequisites each of the two carries.

.. autoclass:: pcapkit.foundation.extraction.Extractor
   :no-members:
   :show-inheritance:

   .. automethod:: __init__

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
   .. automethod:: register_reassembly
   .. automethod:: register_traceflow

   .. automethod:: run

   .. automethod:: import_test
   .. automethod:: make_name

   .. automethod:: record_header
   .. automethod:: record_frames

   .. autoattribute:: __output__
      :no-value:
   .. autoattribute:: __engine__
      :no-value:
   .. autoattribute:: __reassembly__
      :no-value:
   .. autoattribute:: __traceflow__
      :no-value:

   .. automethod:: _cleanup

   .. autoattribute:: _flag_a
   .. autoattribute:: _flag_d
   .. autoattribute:: _flag_e
   .. autoattribute:: _flag_q
   .. autoattribute:: _flag_t
   .. autoattribute:: _flag_v
   .. autoattribute:: _flag_n
   .. autoattribute:: _flag_s

   .. autoattribute:: _ifile
   .. autoattribute:: _ofile

   .. autoattribute:: _frnum
   .. autoattribute:: _reasm
   .. autoattribute:: _trace

   .. autoattribute:: _exnam
   .. autoattribute:: _exeng

   .. autoattribute:: _exlyr
   .. autoattribute:: _exptl

   .. automethod:: __iter__
   .. automethod:: __next__
   .. automethod:: __call__

Type Variables
--------------

.. data:: pcapkit.foundation.extraction._P
   :type: typing.Any

.. |pypcap| replace:: ``pypcap``
.. _pypcap: https://github.com/pynetwork/pypcap
.. |pypcapfile| replace:: ``pypcapfile``
.. _pypcapfile: https://github.com/kisom/pypcapfile
