============================
Reassembled Payload Analysis
============================

.. module:: pcapkit.foundation.analysis

:mod:`pcapkit.foundation.analysis` parses what a
:mod:`pcapkit.foundation.reassembly` engine reassembled into a usable result,
so that a caller does not interpret the raw reassembled octets itself
(:ref:`reassembly-integration`).

.. versionadded:: 1.6.0

.. autofunction:: pcapkit.foundation.analysis.dtls_handshake
