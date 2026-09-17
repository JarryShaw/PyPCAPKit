# -*- coding: utf-8 -*-
"""Character Set Detection
=============================

.. module:: pcapkit.utilities.chardet

:mod:`pcapkit.utilities.chardet` wraps `chardet`_ with a bounded cache, for
turning the bytes of a text field into a :obj:`str`.

.. _chardet: https://chardet.readthedocs.io

"""

import functools

import chardet

__all__ = ['detect']

#: How many distinct bytestrings :func:`detect` will remember. Bounded so that a
#: capture full of never-repeating text cannot retain all of it.
DETECT_CACHE_SIZE = 1024


@functools.lru_cache(maxsize=DETECT_CACHE_SIZE)
def detect(value: 'bytes') -> 'str':
    """Detect the character set of ``value``.

    :func:`chardet.detect` is a pure function of the bytes handed to it, and the
    single most expensive step in turning a text field into a :obj:`str`. The
    strings a capture presents repeat heavily -- an HTTP-heavy capture asked for
    the encoding of ``b'Connection'`` once per message and got the same answer
    every time -- so the verdict is memoised rather than recomputed. The result is
    by construction the one :func:`chardet.detect` would have returned.

    Note:
        The cache is bounded by entry *count*, not by size, and it holds the bytes
        it was keyed on: :func:`functools.lru_cache` caches an argument's *hash*
        but still keeps the argument, since a :obj:`dict` needs the key to settle
        equality on a hash collision. Measured, feeding 20 distinct 1 MB values
        retains 19.1 MB. :data:`DETECT_CACHE_SIZE` therefore caps the entries
        rather than the footprint, which matters because
        :meth:`ProtocolBase.decode
        <pcapkit.protocols.protocol.ProtocolBase.decode>` is public and a caller
        may hand it a whole payload. Use :meth:`detect.cache_clear
        <functools.lru_cache.cache_clear>` to release it in a long-running
        process.

        Two alternatives were tried and rejected. Keying on a *prefix* is
        unsound, since :func:`chardet.detect` is statistical over the whole
        sequence: an ASCII header followed by a UTF-8, Latin-1 or CP1251 body is
        detected as ``ascii`` from its first 256 octets and correctly otherwise,
        three disagreements in six realistic cases. Keying on a digest bounds the
        footprint exactly and was measured retaining 0.0 MB for the same 19 MB of
        input, but it cannot be expressed with :func:`~functools.lru_cache` --
        which keys on what it is passed -- and hand-rolling the eviction was
        judged not worth the six lines.

    Args:
        value: Bytestring whose encoding is to be detected.

    Returns:
        Name of the detected encoding, or ``'utf-8'`` where detection declines to
        name one.

    """
    return chardet.detect(value)['encoding'] or 'utf-8'
