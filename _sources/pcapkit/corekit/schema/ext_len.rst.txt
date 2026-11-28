Extension-Header Length
=======================

.. module:: pcapkit.corekit.schema.ext_len

:mod:`pcapkit.corekit.schema.ext_len` converts between octets and the length
field of an IPv6-extension-style header, which counts 8-octet units not
including the first 8 octets [:rfc:`6564#section-4`], for the extension headers,
the Mobility Header, HIP, the jumbogram lookup and IPv6 reassembly alike.

.. versionadded:: 1.7.0

.. versionchanged:: 1.9.0

   Renamed from ``pcapkit.corekit.schema.extlen`` (:issue:`3153`).

.. versionremoved:: 1.9.0

   ``pcapkit.corekit.schema.extlen``, now
   :mod:`pcapkit.corekit.schema.ext_len` (:issue:`3153`).

.. autofunction:: pcapkit.corekit.schema.ext_len.ext_len_to_octets

.. autofunction:: pcapkit.corekit.schema.ext_len.octets_to_ext_len
