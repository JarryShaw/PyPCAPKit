# -*- coding: utf-8 -*-
"""Schema Helpers
====================

.. module:: pcapkit.corekit.schema

:mod:`pcapkit.corekit.schema` holds the helpers shared across the schema layer:
the functions the field classes, the header schemas, the protocols and the
capture engines all call, one module per group. It is not the header schema
framework, which is :mod:`pcapkit.protocols.schema` and its
:class:`~pcapkit.protocols.schema.schema.Schema`; see :ref:`utilities-or-corekit`.

The package exports nothing itself, so that the field modules importing a helper
from it load no other group: import each helper from its own module.

.. versionadded:: 1.6.0

"""

__all__ = []  # type: list[str]
