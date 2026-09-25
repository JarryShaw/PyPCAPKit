# -*- coding: utf-8 -*-
"""A negative resolved field length must raise ``ProtocolError``, not ``struct.error``.

GitHub issue #805. :meth:`~pcapkit.protocols.schema.schema.Schema.unpack`
decrements ``packet['__length__']`` by each field's *nominal* width
regardless of how many octets the buffer actually had, and a field whose own
``length=lambda pkt: pkt['__length__']``-style callback resolves to that
negative remainder builds a struct template such as ``'-5s'``.
:func:`struct.calcsize` cannot size that and raised a bare
:exc:`struct.error` for it -- not a :exc:`ProtocolError`, not even a
:exc:`ValueError`, uncatchable by ordinary caller code.

Scope, per the issue's own correction of its body: the fix belongs at the
*resolved field length* -- :attr:`~pcapkit.corekit.fields.field.FieldBase.length`
-- not at the running-counter warning (``pcapkit/protocols/schema/schema.py``
around ``packet['__length__'] < 0``), which this module does not touch. See
:mod:`tests.corekit.test_fields_field`'s ``FieldBaseLengthNegativeResolvedLengthTests``
for the property-level unit tests and the unaffected non-negative control.

``read()``'s own ``schema.length > length`` guard (`httpv2.py`) cannot see
this class of input: the crash happens while resolving the *inner* frame's
own fields, during :meth:`Schema.unpack`, before that comparison ever runs.
So these are built by constructing :class:`HTTP` (HTTP/2) directly, which is
how the issue itself reproduces the defect.

"""

from __future__ import annotations

import importlib.util
import io
import struct
import unittest
import warnings

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def http2_frame_bytes(type_: 'int', flags: 'int', sid: 'int', payload: 'bytes') -> 'bytes':
    """Build the wire octets of one HTTP/2 frame.

    Args:
        type_: Frame type octet.
        flags: Frame flags octet.
        sid: Stream identifier.
        payload: The frame payload, header excluded.

    Returns:
        The packed frame, its 3-octet length field counting the whole frame
        (header included), this library's convention.

    """
    return (
        (len(payload) + 9).to_bytes(3, 'big')
        + bytes([type_, flags])
        + sid.to_bytes(4, 'big')
        + payload
    )


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NegativeResolvedLengthUnitTests(unittest.TestCase):
    """The #805 reproduction, and the well-formed inputs it must not touch."""

    def test_goaway_at_sixteen_octets_raises_protocolerror_not_structerror(self) -> None:
        """The issue's own repro: a 16-octet ``GOAWAY`` frame.

        ``stream``+``error`` alone are eight fixed octets, so a 16-octet
        buffer (7 octets of frame-specific payload after the 9-octet header)
        drives ``debug``'s ``length=lambda pkt: pkt['__length__']`` to -1.
        Pre-fix: ``struct.error: bad char in struct format``.
        """
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        data = b'\x00\x00\x15\x07\x00\x00\x00\x00\x00' + b'\xff' * 7
        self.assertEqual(len(data), 16)

        with self.assertRaises(ProtocolError) as ctx:
            HTTPv2(io.BytesIO(data), 16)
        self.assertNotIsInstance(ctx.exception, struct.error)

    def test_goaway_buflens_nine_through_sixteen_all_raise_protocolerror(self) -> None:
        """Every ``GOAWAY`` buffer length the issue names as an escape.

        ``buflen`` 9 through 16: the fixed ``stream``/``error`` fields alone
        need eight payload octets, so every one of these drives ``debug``
        negative.
        """
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for buflen in range(9, 17):
            payload = b'\x00' * (buflen - 9)
            raw = http2_frame_bytes(0x07, 0x00, 0, payload)
            with self.subTest(buflen=buflen):
                with self.assertRaises(ProtocolError) as ctx:
                    HTTPv2(io.BytesIO(raw), buflen)
                self.assertNotIsInstance(ctx.exception, struct.error)

    def test_push_promise_buflens_nine_through_twelve_all_raise_protocolerror(self) -> None:
        """Every ``PUSH_PROMISE`` buffer length the issue names as an escape.

        The promised stream identifier alone is four octets, so buffers 9
        through 12 leave ``fragment`` negative.
        """
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for buflen in range(9, 13):
            payload = b'\x00' * (buflen - 9)
            raw = http2_frame_bytes(0x05, 0x04, 1, payload)
            with self.subTest(buflen=buflen):
                with self.assertRaises(ProtocolError) as ctx:
                    HTTPv2(io.BytesIO(raw), buflen)
                self.assertNotIsInstance(ctx.exception, struct.error)

    def test_an_over_padded_data_frame_raises_protocolerror(self) -> None:
        """``pad_len`` exceeding the payload area, for a ``DATA`` frame."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        payload = bytes([20])  # PADDED, pad_len=20, no data and no padding octets follow
        raw = http2_frame_bytes(0x00, 0x08, 1, payload)

        with self.assertRaises(ProtocolError) as ctx:
            HTTPv2(io.BytesIO(raw), len(raw))
        self.assertNotIsInstance(ctx.exception, struct.error)

    def test_a_well_formed_goaway_frame_still_parses_cleanly(self) -> None:
        """Control: a ``GOAWAY`` frame whose buffer matches its declared length.

        The fix is a ``try``/``except struct.error`` around the same
        :func:`struct.calcsize` call as before, so a resolved length that
        never goes negative must parse identically to pre-fix -- no
        exception, no warning.
        """
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        debug = b'ok'
        payload = (5).to_bytes(4, 'big') + (0).to_bytes(4, 'big') + debug
        raw = http2_frame_bytes(0x07, 0x00, 1, payload)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            info = HTTPv2(io.BytesIO(raw), len(raw)).info

        self.assertEqual(info.debug_data, debug)
        self.assertEqual([str(w.message) for w in caught], [])

if __name__ == '__main__':
    unittest.main()
