# -*- coding: utf-8 -*-
"""An SCTP parameter or error cause given as empty raw octets is refused.

GitHub issue #2723: ``_make_sctp_parameters`` and ``_make_sctp_causes`` kept an
empty raw item in the list they return. Its packed octets parse back with no
item in its place, so the made header was kept, and reading it then took the
empty octets for a schema: ``[b'']`` raised a bare ``AttributeError``. Empty
octets raise ``ProtocolError``, as the other malformed items in those
branches do.

A raw item that holds its type or code builds as given, which the cases
below pin against :rfc:`9260`: the IPv4 Address parameter of
:rfc:`9260#section-3.3.2.1` after the 20 octets of an INIT chunk's fixed
fields, and the Invalid Stream Identifier cause of
:rfc:`9260#section-3.3.10.1` after the 4 octets of an ABORT chunk's header,
each chunk's Chunk Length counting it.

Every case builds its own octets in memory and reads no capture. :class:`SCTP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class

#: An IPv4 Address parameter, of 192.0.2.1.
PARAMETER = b'\x00\x05\x00\x08\xc0\x00\x02\x01'
#: An Invalid Stream Identifier cause, of stream 1.
CAUSE = b'\x00\x01\x00\x08\x00\x01\x00\x00'


class TestSCTPEmptyRawItem(unittest.TestCase):
    """Empty raw octets raise ``ProtocolError``; a whole raw item builds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_empty_parameter_is_refused(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        for chunk in (Chunk.Initiation, Chunk.Initiation_Acknowledgement):
            for parameters in ([b''], [PARAMETER, b'']):
                with self.subTest(chunk=chunk, parameters=parameters):
                    with self.assertRaisesRegex(ProtocolError, r"invalid parameter: b'' holds no type field"):
                        SCTP(chunks=[(chunk, {'parameters': parameters})])

    def test_empty_cause_is_refused(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        for chunk in (Chunk.Abort, Chunk.Operation_Error):
            for error in ([b''], [CAUSE, b'']):
                with self.subTest(chunk=chunk, error=error):
                    with self.assertRaisesRegex(ProtocolError, r"invalid error cause: b'' holds no code field"):
                        SCTP(chunks=[(chunk, {'error': error})])

    def test_raw_parameter_builds_as_given(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        built = SCTP(chunks=[(Chunk.Initiation, {'parameters': [PARAMETER]})]).data
        self.assertEqual(built[12], Chunk.Initiation)
        self.assertEqual(int.from_bytes(built[14:16], 'big'), 28)  # 20 fixed octets and the parameter
        self.assertEqual(built[32:], PARAMETER)

    def test_raw_cause_builds_as_given(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        built = SCTP(chunks=[(Chunk.Abort, {'error': [CAUSE]})]).data
        self.assertEqual(built[12], Chunk.Abort)
        self.assertEqual(int.from_bytes(built[14:16], 'big'), 12)  # the chunk header and the cause
        self.assertEqual(built[16:], CAUSE)


if __name__ == '__main__':
    unittest.main()
