# -*- coding: utf-8 -*-
"""The ``httpv2-frame`` family: HTTP/2 frames.

A family module of :file:`examples/generators/options.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
# Deferring these is the design, as in options.py -- see its module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/options.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any


def _httpv2_registry() -> 'Any':
    from pcapkit.protocols.application.httpv2 import HTTPv2
    return HTTPv2.__frame__


def _httpv2_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.http.frame import Frame as Enum_Frame
    from pcapkit.const.http.setting import Setting as Enum_Setting
    return {
        # ``settings=None``, the default, matches none of the accepted forms.
        Enum_Frame.SETTINGS: {'settings': [(Enum_Setting.HEADER_TABLE_SIZE, 4096)]},
        Enum_Frame.GOAWAY: {'debug_data': b'\xde\xad'},
        # A server-initiated stream is even and non-zero (RFC 9113 Section 5.1.1).
        Enum_Frame.PUSH_PROMISE: {'promised_sid': 2},
    }


#: HTTP/2 frame types that apply to the connection as a whole and so are sent
#: on stream 0 (RFC 9113 Sections 6.5, 6.7 and 6.8). Every other frame type is
#: sent on :data:`HTTPV2_STREAM`.
HTTPV2_CONNECTION_FRAMES = (4, 6, 7)  # SETTINGS, PING, GOAWAY

#: Stream identifier of every stream-level HTTP/2 frame: the first
#: client-initiated stream (RFC 9113 Section 5.1.1). ``DATA``, ``HEADERS``,
#: ``PRIORITY``, ``RST_STREAM``, ``PUSH_PROMISE`` and ``CONTINUATION`` are a
#: connection error on stream 0, and ``WINDOW_UPDATE`` may use either.
HTTPV2_STREAM = 1


def _httpv2_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.application.httpv2 import HTTPv2

    sid = 0 if int(code) in HTTPV2_CONNECTION_FRAMES else HTTPV2_STREAM
    return HTTPv2(type=code, sid=sid, frame=dict(kwargs))


def _httpv2_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.application.httpv2 import HTTPv2
    return HTTPv2(octets, len(octets))


def _httpv2_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _httpv2_rebuild(frame: 'Any') -> 'Any':
    from pcapkit.protocols.application.httpv2 import HTTPv2

    # ``HTTP.make`` ORs ``flags`` into the bits the ``_make_http_*`` constructor
    # derives from ``frame``, and that constructor knows only the flags its
    # frame type defines. So the raw flags octet is passed on, as
    # ``HTTP._make_data`` does, or a bit the type leaves undefined is dropped.
    # ``reserved`` is passed on for the same reason: ``make`` defaults it to 0.
    return HTTPv2(type=frame.type, sid=frame.sid, reserved=frame.reserved,
                flags=frame.flags.__value__ if frame.flags is not None else 0,
                frame=frame)


#: The families this module adds.
FAMILIES = (
    generator.Family('httpv2-frame', _httpv2_registry, _httpv2_overrides,
                     _httpv2_build, _httpv2_parse, _httpv2_extract, _httpv2_rebuild,
                     capture='options-transport.pcap', envelope='tcp'),
)
