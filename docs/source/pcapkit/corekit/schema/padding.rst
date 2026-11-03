Padding Arithmetic
==================

.. module:: pcapkit.corekit.schema.padding

:mod:`pcapkit.corekit.schema.padding` counts the octets of padding that take a
length to a boundary, for the padding fields, the schemas' ``length`` callbacks, the
protocols' makers and the capture engines alike. It is one of the
:mod:`pcapkit.corekit.schema` helpers shared across the schema layer, not part of
the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

.. autofunction:: pcapkit.corekit.schema.padding.pad_length
