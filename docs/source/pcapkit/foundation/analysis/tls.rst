===================
TLS Record Analysis
===================

.. module:: pcapkit.foundation.analysis.tls

:mod:`pcapkit.foundation.analysis.tls` contains
:func:`~pcapkit.foundation.analysis.tls.tls_record` only, which decodes a TLS record
that :class:`~pcapkit.foundation.reassembly.tls.reassembly.TLS` reassembled from a TCP
stream (:rfc:`9846#section-5`). The decode itself is :meth:`TLS.analyze_record
<pcapkit.protocols.application.tls.protocol.TLS.analyze_record>`.

.. versionadded:: 1.9.0

.. autofunction:: pcapkit.foundation.analysis.tls.tls_record
