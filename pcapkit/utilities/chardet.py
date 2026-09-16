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

__all__ = ['detect_charset']

#: How many distinct bytestrings :func:`detect_charset` will remember. Bounded
#: so that a capture full of never-repeating text cannot retain all of it.
DETECT_CACHE_SIZE = 1024

#: Longest bytestring :func:`detect_charset` will put in the cache. Chosen from
#: measurement: across ``http.pcap``, ``http6.cap`` and
#: ``many_interfaces.pcapng`` every value reaching detection was at most 116
#: octets, with a 95th percentile of 52, so this keeps every repeating string a
#: real capture presents while capping what the cache can retain.
DETECT_CACHE_MAX_BYTES = 256


@functools.lru_cache(maxsize=DETECT_CACHE_SIZE)
def _detect_charset_cached(value: 'bytes') -> 'str':
    """Detect the character set of a short ``value``, memoised.

    Args:
        value: Bytestring whose encoding is to be detected.

    Returns:
        Name of the detected encoding, or ``'utf-8'`` where detection declines
        to name one.

    """
    return chardet.detect(value)['encoding'] or 'utf-8'


def detect_charset(value: 'bytes') -> 'str':
    """Detect the character set of ``value``.

    :func:`chardet.detect` is a pure function of the bytes handed to it, and the
    single most expensive step in turning a text field into a :obj:`str`. The
    strings a capture presents repeat heavily -- an HTTP-heavy capture asked for
    the encoding of ``b'Connection'`` once per message and got the same answer
    every time -- so the verdict is memoised on the bytes rather than recomputed.
    The result is by construction the one :func:`chardet.detect` would have
    returned.

    Long values bypass the cache. :meth:`ProtocolBase.decode
    <pcapkit.protocols.protocol.ProtocolBase.decode>` is public, so a caller may
    hand this an entire payload, and :func:`~functools.lru_cache` bounds how many
    entries it keeps rather than how large they are -- 1024 multi-megabyte
    payloads would be retained for the life of the process. Skipping the cache
    above :data:`DETECT_CACHE_MAX_BYTES` costs such a call nothing it was not
    already paying, since a payload that size is unlikely to recur anyway.

    Note:
        Keying the cache on a *prefix* of a long value would bound the memory
        while still caching it, but it is not sound: :func:`chardet.detect` is
        statistical over the whole sequence, so a prefix can disagree with the
        value it came from. Measured on realistic inputs, an ASCII header
        followed by a UTF-8, Latin-1 or CP1251 body is detected as ``ascii`` from
        its first 256 octets and correctly otherwise -- three disagreements in
        six cases, each of which would decode the body wrongly. Hashing the full
        value would be both sound and bounded, and is the thing to reach for if a
        capture ever does present large recurring text.

    Args:
        value: Bytestring whose encoding is to be detected.

    Returns:
        Name of the detected encoding, or ``'utf-8'`` where detection declines
        to name one.

    """
    if len(value) > DETECT_CACHE_MAX_BYTES:
        return chardet.detect(value)['encoding'] or 'utf-8'
    return _detect_charset_cached(value)
