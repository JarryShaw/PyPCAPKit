:mod:`DPKT <dpkt>` Tools
========================

.. module:: pcapkit.toolkit.dpkt

:mod:`pcapkit.toolkit.dpkt` contains all you need for
:mod:`pcapkit` handy usage with `DPKT`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _DPKT: https://dpkt.readthedocs.io

.. autofunction:: pcapkit.toolkit.dpkt.ipv4_reassembly
.. autofunction:: pcapkit.toolkit.dpkt.ipv6_reassembly
.. autofunction:: pcapkit.toolkit.dpkt.tcp_reassembly
.. autofunction:: pcapkit.toolkit.dpkt.tcp_traceflow

.. autofunction:: pcapkit.toolkit.dpkt.ipv6_hdr_len
.. autofunction:: pcapkit.toolkit.dpkt.packet2chain
.. autofunction:: pcapkit.toolkit.dpkt.packet2dict
