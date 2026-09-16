# -*- coding: utf-8 -*-
"""Character Set Detection
=============================

.. module:: pcapkit.utilities.chardet

:mod:`pcapkit.utilities.chardet` wraps `chardet`_ with a bounded cache, for
turning the bytes of a text field into a :obj:`str`.

.. _chardet: https://chardet.readthedocs.io

"""

import collections
import hashlib
from typing import TYPE_CHECKING

import chardet

__all__ = ['detect']

if TYPE_CHECKING:
    from collections import OrderedDict

#: How many distinct bytestrings :func:`detect` will remember. Bounded so that a
#: capture full of never-repeating text cannot retain all of it.
DETECT_CACHE_SIZE = 1024

#: Digest length, in octets, of the key :func:`detect` caches under. 32 octets is
#: 256 bits, so a collision -- which would hand one bytestring another's verdict
#: -- is not a thing that happens; halving :func:`~hashlib.blake2b`'s default 64
#: halves what the cache retains per entry for no practical loss.
DETECT_DIGEST_SIZE = 32

#: Detected encodings, keyed by digest of the bytes they were detected from, least
#: recently used first. An :class:`~collections.OrderedDict` rather than
#: :func:`functools.lru_cache` because the cache key is a digest of the argument
#: rather than the argument itself, which ``lru_cache`` cannot express.
_cache = collections.OrderedDict()  # type: OrderedDict[bytes, str]


def detect(value: 'bytes') -> 'str':
    """Detect the character set of ``value``.

    :func:`chardet.detect` is a pure function of the bytes handed to it, and the
    single most expensive step in turning a text field into a :obj:`str`. The
    strings a capture presents repeat heavily -- an HTTP-heavy capture asked for
    the encoding of ``b'Connection'`` once per message and got the same answer
    every time -- so the verdict is memoised rather than recomputed. The result is
    by construction the one :func:`chardet.detect` would have returned.

    The cache is keyed on a :func:`~hashlib.blake2b` digest of the bytes rather
    than on the bytes themselves. A cache bounded by entry *count* is not bounded
    in size, and :meth:`ProtocolBase.decode
    <pcapkit.protocols.protocol.ProtocolBase.decode>` is public, so keying on the
    value would let :data:`DETECT_CACHE_SIZE` whole payloads be retained for the
    life of the process. A fixed-width digest caps that at
    :data:`DETECT_CACHE_SIZE` × :data:`DETECT_DIGEST_SIZE` regardless of what is
    passed, and hashing is cheap beside a detection that already walks the same
    bytes.

    Note:
        Two cheaper-looking alternatives are both wrong. Keying on a *prefix* is
        unsound, since :func:`chardet.detect` is statistical over the whole
        sequence: measured on realistic inputs, an ASCII header followed by a
        UTF-8, Latin-1 or CP1251 body is detected as ``ascii`` from its first 256
        octets and correctly otherwise -- three disagreements in six cases, each
        of which would decode the body wrongly. Skipping the cache above a size
        threshold is sound but leans on sample captures being representative of
        real traffic, which they are not: a capture full of large repeated text is
        exactly the case that most wants the cache.

    Args:
        value: Bytestring whose encoding is to be detected.

    Returns:
        Name of the detected encoding, or ``'utf-8'`` where detection declines to
        name one.

    """
    digest = hashlib.blake2b(value, digest_size=DETECT_DIGEST_SIZE).digest()
    try:
        charset = _cache[digest]
    except KeyError:
        charset = chardet.detect(value)['encoding'] or 'utf-8'
        _cache[digest] = charset
        if len(_cache) > DETECT_CACHE_SIZE:
            _cache.popitem(last=False)
    else:
        _cache.move_to_end(digest)
    return charset
