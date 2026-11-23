# -*- coding: utf-8 -*-
"""constants the HTTP family shares

.. versionadded:: 1.7.0

"""
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

__all__ = []  # type: list[str]

#: The HTTP/2 connection preface (:rfc:`9113#section-3.4`), which opens every
#: HTTP/2 connection. Its method ``PRI`` is registered as one no actual client
#: uses (:rfc:`7540#section-11.6`), so a prefix match identifies HTTP/2, and
#: :meth:`HTTP._guess_version
#: <pcapkit.protocols.application.http.protocol.HTTP._guess_version>` tests it
#: before any parse.
_HTTP2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

#: What :rfc:`9113#section-6` allows a sender to put in the frame header of each
#: frame type it defines: the flags that type defines, and the stream identifier
#: it is sent on -- ``True`` for a non-zero stream, ``False`` for stream 0 and
#: :obj:`None` for either. :meth:`HTTP._guess_version
#: <pcapkit.protocols.application.http.protocol.HTTP._guess_version>` checks a bare
#: frame against this before its HTTP/2 trial parse; see
#: :func:`~pcapkit.protocols.application.http.protocol._test_http2_frame`.
_HTTP2_FRAME_RULES = {
    0x0: (0x09, True),    # DATA: END_STREAM, PADDED (Section 6.1)
    0x1: (0x2D, True),    # HEADERS: END_STREAM, END_HEADERS, PADDED, PRIORITY (Section 6.2)
    0x2: (0x00, True),    # PRIORITY (Section 6.3)
    0x3: (0x00, True),    # RST_STREAM (Section 6.4)
    0x4: (0x01, False),   # SETTINGS: ACK (Section 6.5)
    0x5: (0x0C, True),    # PUSH_PROMISE: END_HEADERS, PADDED (Section 6.6)
    0x6: (0x01, False),   # PING: ACK (Section 6.7)
    0x7: (0x00, False),   # GOAWAY (Section 6.8)
    0x8: (0x00, None),    # WINDOW_UPDATE: either stream (Section 6.9)
    0x9: (0x04, True),    # CONTINUATION: END_HEADERS (Section 6.10)
}  # type: dict[int, tuple[int, Optional[bool]]]

# HTTP method token, case-sensitive (RFC 9110, section 9.1). Anchored at the end
# too, as ``re.match`` anchors only at the start and would take ``G`` of ``Get``.
_RE_METHOD = re.compile(rb"(?P<method>[A-Z][A-Z-]*)\Z")  # RFC 9110, section 16.1.1, 9.1, 5.6.2
# Regular expression to match HTTP version string.
_RE_VERSION = re.compile(rb"HTTP/(?P<version>\d\.\d)")
# HTTP status code, ``3DIGIT`` (RFC 9112, section 4). Anchored as ``_RE_METHOD``
# is: ``HTTPv1`` takes ``int()`` of the raw token, so a prefix match would let
# ``200x`` through to a bare ``ValueError`` rather than a ``ProtocolError``.
_RE_STATUS = re.compile(rb'\d{3}\Z')

# The HTTP/2 preface's header block, ``PRI * HTTP/2.0``, as ``HTTPv1.read`` splits
# it off at the first CRLFCRLF. The patterns above accept it, so
# ``HTTPv1._read_http_header`` and ``test_start_line`` refuse it by name.
_HTTP2_PREFACE_HEADER = _HTTP2_PREFACE.split(b'\r\n\r\n', maxsplit=1)[0]
