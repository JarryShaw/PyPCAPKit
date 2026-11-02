=====================
TCP Datagram Analysis
=====================

.. module:: pcapkit.foundation.analysis.tcp

:mod:`pcapkit.foundation.analysis.tcp` contains
:func:`~pcapkit.foundation.analysis.tcp.tcp_datagram` only, which parses the
application-layer payload of a TCP datagram that
:class:`~pcapkit.foundation.reassembly.tcp.TCP` reassembled.

.. autofunction:: pcapkit.foundation.analysis.tcp.tcp_datagram
