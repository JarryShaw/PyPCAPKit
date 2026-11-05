===============================
DTLS Handshake-Message Analysis
===============================

.. module:: pcapkit.foundation.analysis.dtls

:mod:`pcapkit.foundation.analysis.dtls` contains
:func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` only, which decodes a
DTLS handshake message that :class:`~pcapkit.foundation.reassembly.dtls.DTLS`
reassembled (:rfc:`6347#section-4.2.3`). The decode itself is
:meth:`DTLS.analyze_handshake
<pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>` (:issue:`2622`).

.. versionadded:: 1.6.0

.. autofunction:: pcapkit.foundation.analysis.dtls.dtls_handshake
