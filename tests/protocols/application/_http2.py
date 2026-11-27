# -*- coding: utf-8 -*-
"""Shared HTTP/2 wire builders for the modules beside this one. C.f. #3148.

Nothing here imports :mod:`pcapkit`, so importing this module at the top of a
test module leaves :func:`~tests._support.reimport_once_per_class` the only
import of the package that test sees.

"""

from __future__ import annotations

__all__ = ['http2_frame_bytes']


def http2_frame_bytes(type_: 'int', flags: 'int', sid: 'int', payload: 'bytes') -> 'bytes':
    """Build the wire octets of one HTTP/2 frame.

    Args:
        type_: Frame type octet.
        flags: Frame flags octet.
        sid: Stream identifier.
        payload: The frame payload, header excluded.

    Returns:
        The packed frame, its 3-octet length field counting the payload only,
        the 9-octet header excluded [:rfc:`9113#section-4.1`].

    """
    return (
        len(payload).to_bytes(3, 'big')
        + bytes([type_, flags])
        + sid.to_bytes(4, 'big')
        + payload
    )
