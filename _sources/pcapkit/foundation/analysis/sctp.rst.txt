==========================
SCTP User-Message Analysis
==========================

.. module:: pcapkit.foundation.analysis.sctp

:mod:`pcapkit.foundation.analysis.sctp` contains
:func:`~pcapkit.foundation.analysis.sctp.sctp_message` only, which parses the
user data of an SCTP user message that
:class:`~pcapkit.foundation.reassembly.sctp.reassembly.SCTP` reassembled, through
:meth:`SCTP.analyze <pcapkit.protocols.transport.sctp.protocol.SCTP.analyze>`.

.. versionadded:: 1.9.0

.. autofunction:: pcapkit.foundation.analysis.sctp.sctp_message
