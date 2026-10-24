Timestamp Conversion
====================

.. module:: pcapkit.utilities.timestamp

:mod:`pcapkit.utilities.timestamp` converts a UNIX timestamp to an aware
:class:`~datetime.datetime` without the C library's range (:issue:`2099`), and
a :class:`~datetime.datetime` back to a UNIX timestamp without GraalPy's lost
second before 1970 (:issue:`2134`). It is shared by the PCAP and PCAP-NG readers
and writers and the MH timestamp options, which is why it lives here rather than
beside any one of them.

.. autofunction:: pcapkit.utilities.timestamp.fromtimestamp

.. autofunction:: pcapkit.utilities.timestamp.totimestamp
