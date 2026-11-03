# -*- coding: utf-8 -*-
"""Padding Arithmetic
========================

.. module:: pcapkit.corekit.schema.padding

:mod:`pcapkit.corekit.schema.padding` counts the octets of padding that take a
length to a boundary, for the padding fields, the schemas' ``length`` callbacks, the
protocols' makers and the capture engines alike. It is one of the
:mod:`pcapkit.corekit.schema` helpers shared across the schema layer, not part of
the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

"""

from pcapkit.utilities.exceptions import FieldValueError, IntError

__all__ = ['pad_length']


def pad_length(length: 'int', align: 'int') -> 'int':
    """Octets of padding that take ``length`` octets to an ``align``-octet boundary.

    Args:
        length: Octets to be padded.
        align: Boundary, in octets.

    Returns:
        ``-length % align``: from ``0``, where ``length`` is already a multiple
        of ``align``, to ``align - 1``.

    Raises:
        IntError: If ``align`` is not an :obj:`int`, or is a :obj:`bool`.
        FieldValueError: If ``align`` is not positive.

    A schema's ``length`` callbacks are handed the packet data, not a
    protocol, so this is a plain function and not a protocol method.
    :class:`~pcapkit.corekit.fields.strings.PaddingField` sizes itself by it
    when given ``align``.

    .. versionadded:: 1.6.0

    """
    if isinstance(align, bool) or not isinstance(align, int):
        raise IntError(f'align must be an int, not {align!r}')
    if align < 1:
        raise FieldValueError(f'align must be positive, not {align!r}')
    return -length % align
