====================
IP Datagram Analysis
====================

.. module:: pcapkit.foundation.analysis.ip

:mod:`pcapkit.foundation.analysis.ip` contains
:func:`~pcapkit.foundation.analysis.ip.ip_datagram` only, which parses the
payload of an IPv4 or IPv6 datagram that
:class:`~pcapkit.foundation.reassembly.ipv4.reassembly.IPv4` or
:class:`~pcapkit.foundation.reassembly.ipv6.reassembly.IPv6` reassembled.

.. versionadded:: 1.6.0

.. autofunction:: pcapkit.foundation.analysis.ip.ip_datagram
