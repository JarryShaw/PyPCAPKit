Extension-Header Length
=======================

.. module:: pcapkit.corekit.schema.extlen

:mod:`pcapkit.corekit.schema.extlen` converts between octets and the length
field of an IPv6-extension-style header, which counts 8-octet units not
including the first 8 octets [:rfc:`6564#section-4`], for the extension headers,
the Mobility Header, HIP, the jumbogram lookup and IPv6 reassembly alike.

.. versionadded:: 1.7.0

.. autofunction:: pcapkit.corekit.schema.extlen.ext_len_to_octets

.. autofunction:: pcapkit.corekit.schema.extlen.octets_to_ext_len
