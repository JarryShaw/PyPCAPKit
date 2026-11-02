============================
Reassembled Payload Analysis
============================

.. module:: pcapkit.foundation.analysis

:mod:`pcapkit.foundation.analysis` parses what a
:mod:`pcapkit.foundation.reassembly` engine reassembled into a usable result,
so that a caller does not interpret the raw reassembled octets itself
(:ref:`reassembly-integration`). Each function is a public wrapper: the parse
itself is a method of the protocol class, which the function calls.

.. versionadded:: 1.6.0

.. toctree::
   :maxdepth: 2

   ip
   tcp
   dtls
