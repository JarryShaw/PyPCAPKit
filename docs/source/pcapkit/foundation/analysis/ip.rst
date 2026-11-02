====================
IP Datagram Analysis
====================

.. module:: pcapkit.foundation.analysis.ip

:mod:`pcapkit.foundation.analysis.ip` contains
:func:`~pcapkit.foundation.analysis.ip.ip_datagram` only, which parses the
payload of an IPv4 or IPv6 datagram that
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4` or
:class:`~pcapkit.foundation.reassembly.ipv6.IPv6` reassembled.

.. autofunction:: pcapkit.foundation.analysis.ip.ip_datagram
