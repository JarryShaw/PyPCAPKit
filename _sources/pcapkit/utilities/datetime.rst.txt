Timestamp Conversion
====================

.. module:: pcapkit.utilities.datetime

:mod:`pcapkit.utilities.datetime` converts a UNIX timestamp to an aware
:class:`~datetime.datetime` without the C library's range (:issue:`2099`), and
a :class:`~datetime.datetime` back to a UNIX timestamp without GraalPy's lost
second before 1970 (:issue:`2134`). The PCAP and PCAP-NG readers and writers and
the MH timestamp options share it, so it lives beside none of them.

.. autofunction:: pcapkit.utilities.datetime.fromtimestamp

.. autofunction:: pcapkit.utilities.datetime.totimestamp
