Timestamp Conversion
====================

.. module:: pcapkit.utilities.timestamp

:mod:`pcapkit.utilities.timestamp` converts a UNIX timestamp to an aware
:class:`~datetime.datetime` without the C library's range (:issue:`2099`). It is
shared by the PCAP and PCAP-NG readers and the MH timestamp options, which is
why it lives here rather than beside any one of them.

.. function:: fromtimestamp(timestamp, tz)

   ``datetime.datetime.fromtimestamp(timestamp, tz)`` as 64-bit Linux computes
   it, on every platform: whole seconds and microseconds split from a float as
   CPython splits them, rounding half to even, then added to the UNIX epoch and
   rendered in ``tz``. The standard library breaks the instant down with the C
   library's ``gmtime()``, whose range on Windows is 1970 to 3000, so there it
   raises :exc:`OSError` for instants :class:`~datetime.datetime` holds.

   :raises ValueError: if ``timestamp`` is NaN or names a year outside 1 to 9999
   :raises OverflowError: if ``timestamp`` is past a 64-bit ``time_t``, or ``tz``
      moves the result out of range

   .. versionadded:: 1.5.0

      Every capture and MH timestamp is converted with it (:issue:`2099`).
