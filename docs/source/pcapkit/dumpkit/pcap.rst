PCAP Dumper
===========

.. module:: pcapkit.dumper.pcap

:mod:`pcapkit.dumpkit.pcap` is the dumper for :mod:`pcapkit` implementation,
specifically for PCAP format, which is alike those described in
:mod:`dictdumper`.

.. autoclass:: pcapkit.dumpkit.pcap.PCAPIO
   :no-members:
   :show-inheritance:

   :param fname: output file name
   :param protocol: data link type
   :param byteorder: header byte order
   :param nanosecond: nanosecond-resolution file flag
   :param \*\*kwargs: arbitrary keyword arguments

   .. autoproperty:: kind
