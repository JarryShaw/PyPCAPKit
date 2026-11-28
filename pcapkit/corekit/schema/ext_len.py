# -*- coding: utf-8 -*-
"""Extension-Header Length
=============================

.. module:: pcapkit.corekit.schema.ext_len

:mod:`pcapkit.corekit.schema.ext_len` converts between octets and the length
field of an IPv6-extension-style header, which counts 8-octet units not
including the first 8 octets [:rfc:`6564#section-4`], for the extension headers,
the Mobility Header, HIP, the jumbogram lookup and IPv6 reassembly alike. It is
one of the :mod:`pcapkit.corekit.schema` helpers shared across the schema layer,
not part of the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.7.0

.. versionchanged:: 1.9.0

   Renamed from ``pcapkit.corekit.schema.extlen`` (:issue:`3153`).

.. versionremoved:: 1.9.0

   ``pcapkit.corekit.schema.extlen``, now
   :mod:`pcapkit.corekit.schema.ext_len` (:issue:`3153`).

"""

__all__ = ['ext_len_to_octets', 'octets_to_ext_len']


def ext_len_to_octets(ext_len: 'int') -> 'int':
    """Octets of a header whose length field is ``ext_len``.

    Args:
        ext_len: Length field, in 8-octet units not including the first 8
            octets, as ``Hdr Ext Len`` [:rfc:`8200#section-4.3`], MH's ``Header
            Len`` [:rfc:`6275#section-6.1.1`] and HIP's ``Header Length``
            [:rfc:`7401#section-5.1`] count.

    Returns:
        ``(ext_len + 1) * 8``.

    .. versionadded:: 1.7.0

    """
    return (ext_len + 1) * 8


def octets_to_ext_len(length: 'int') -> 'int':
    """Length field of a header of ``length`` octets, the inverse of :func:`ext_len_to_octets`.

    Args:
        length: Octets of the header, the first 8 included.

    Returns:
        ``length // 8 - 1``, rounded down where ``length`` is not a multiple of
        8; a maker that must not declare fewer octets than it packs pads
        ``length`` first.

    .. versionadded:: 1.7.0

    """
    return length // 8 - 1
