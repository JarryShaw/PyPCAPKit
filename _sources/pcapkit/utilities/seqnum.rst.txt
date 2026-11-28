Sequence Number Arithmetic
==========================

.. module:: pcapkit.utilities.seqnum

:mod:`pcapkit.utilities.seqnum` places a 32-bit sequence number on one unbounded
line, as :rfc:`9293#section-3.4` compares TCP sequence numbers. TCP and TLS
reassembly share it, so it lives beside neither.

.. versionadded:: 1.9.0

.. autofunction:: pcapkit.utilities.seqnum.unwrap
