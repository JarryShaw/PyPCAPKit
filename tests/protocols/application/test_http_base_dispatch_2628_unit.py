# -*- coding: utf-8 -*-
"""The HTTP family base follows the versioned-family rules. C.f. #2628.

The rules are #2574's: ``version`` names the member, no field picks one and no
member is a default. So building :class:`~pcapkit.protocols.application.http.protocol.HTTP`
from fields, or calling its ``make``, raises without ``version``; v1.5.1 built
HTTP/1.* by default, and #2544's ``_dispatch_fields`` picked HTTP/2 for a field
only HTTP/2 takes. Its ``from_data`` gives the member whose data model it is
handed and refuses a ``dict``, which v1.5.1 rebuilt by its ``receipt`` or ``sid``
key. Octets dispatch without ``version``, since HTTP octets carry their own;
#2544's module covers that. A member takes ``version`` only as its own, as ICMP's
do. The base is concrete, so a direct subclass of it parses as itself.

The checks are :mod:`tests.protocols._versioned_base`'s; this module holds the
family's tables, and the checks only HTTP's ``make`` and preface need. Every case
builds its own octets in memory and reads no capture.

"""

import unittest

from tests.protocols._versioned_base import FromDataByModel

#: An HTTP/1.1 request and an HTTP/2 ``DATA`` frame on stream 1.
MESSAGES = {
    1: b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n',
    2: bytes.fromhex('000000000000000001'),
}

#: The refusal of fields given no ``version``.
NO_VERSION_FIELDS = '^HTTP: no version to build with; pass version=1 or version=2$'


def fields(version: 'int') -> 'dict[str, object]':
    """Fields only the member of ``version`` takes."""
    from pcapkit.const.http.frame import Frame

    return {'method': 'GET', 'uri': '/'} if version == 1 else {'type': Frame.DATA, 'sid': 1}


class HTTPBaseVersionRuleTests(FromDataByModel, unittest.TestCase):
    """``version`` alone picks the member; no field, key or default does."""

    BASE = 'pcapkit.protocols.application.http.protocol:HTTP'
    MEMBERS = {1: 'pcapkit.protocols.application.httpv1.protocol:HTTPv1',
               2: 'pcapkit.protocols.application.httpv2.protocol:HTTPv2'}
    OCTETS = {'HTTP/1.1 request': (MESSAGES[1], 1), 'HTTP/2 DATA frame': (MESSAGES[2], 2)}
    BAD_VERSIONS = (0, 3, True, '1', 1.0, 2.0)
    CUSTOM = (1, 'pcapkit.protocols.application.httpv1.schema:HTTPv1',
              'pcapkit.protocols.application.httpv1.data:HTTPv1', {'method': 'GET', 'uri': '/'})
    ABSTRACT = False
    NOT_A_DATA_MODEL = '^HTTP: invalid data: must be an HTTPv1 or HTTPv2 data model$'

    def fields(self, version: 'int') -> 'dict[str, object]':
        return fields(version)

    def cases_from_fields(self) -> 'dict[str, tuple[dict[str, object], int, object]]':
        return {'HTTP/1 request': (fields(1), 1, None), 'HTTP/2 DATA frame': (fields(2), 2, MESSAGES[2])}

    def versionless_fields(self) -> 'dict[str, dict[str, object]]':
        """Even a field only one member takes, ``preface`` included."""
        return {'no fields': {}, 'HTTP/1 fields': fields(1), 'HTTP/2 fields': fields(2),
                'preface': {'preface': True}, 'false preface': {'preface': False}}

    def foreign_fields(self) -> 'dict[int, dict[str, object]]':
        return {1: {'sid': 1}}

    def test_make_has_no_default_version(self) -> None:
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        for version in (1, 2):
            with self.subTest(fields=version):
                with self.assertRaisesRegex(ProtocolError, NO_VERSION_FIELDS):
                    HTTP.make(object.__new__(HTTP), **fields(version))  # type: ignore[arg-type]
                schema = HTTP.make(object.__new__(HTTP), version=version, **fields(version))  # type: ignore[arg-type]
                self.assertEqual(schema.pack(), self.member(version).from_fields(**fields(version)).data)

    def test_http1_refuses_a_preface(self) -> None:
        """``pack`` writes the preface for any member, so HTTP/1 refuses it, built directly too."""
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        for label, build in (('base', lambda: HTTP.from_fields(version=1, preface=True, **fields(1))),
                             ('member', lambda: self.member(1).from_fields(preface=True, **fields(1))),
                             ('make', lambda: HTTP.make(object.__new__(HTTP), version=1,  # type: ignore[arg-type]
                                                        preface=True, **fields(1)))):
            with self.subTest(built=label):
                with self.assertRaisesRegex(ProtocolError, '^HTTP/1: connection preface is HTTP/2 only$'):
                    build()
        self.assertEqual(self.member(1).from_fields(preface=False, **fields(1)).data, self.member(1).from_fields(**fields(1)).data)


if __name__ == '__main__':
    unittest.main()
