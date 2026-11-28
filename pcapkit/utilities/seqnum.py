# -*- coding: utf-8 -*-
"""Sequence Number Arithmetic
================================

.. module:: pcapkit.utilities.seqnum

:mod:`pcapkit.utilities.seqnum` places a 32-bit sequence number on one unbounded
line, as :rfc:`9293#section-3.4` compares TCP sequence numbers, so a stream crossing
``2 ** 32`` continues past it rather than back at zero.

.. versionadded:: 1.9.0

"""

__all__ = ['unwrap']

#: Half the 32-bit sequence space, the farthest two compared numbers may lie apart.
_HALF = 1 << 31
#: The 32-bit sequence space.
_SPACE = 1 << 32


def unwrap(seq: 'int', ref: 'int') -> 'int':
    """Place a 32-bit sequence number on the unwrapped line near ``ref``.

    Arguments:
        seq: sequence number as carried on the wire, i.e. modulo ``2 ** 32``
        ref: unwrapped sequence number ``seq`` is expected to be near

    Returns:
        The integer congruent to ``seq`` modulo ``2 ** 32`` that lies within
        ``2 ** 31`` of ``ref``, which is how :rfc:`9293#section-3.4` compares
        sequence numbers.

    """
    return ref + (seq - ref + _HALF) % _SPACE - _HALF
