# -*- coding: utf-8 -*-
"""The HTTP family base follows the versioned-family rules. C.f. #2628.

The rules are #2574's: ``version`` names the member, no field picks one and no
member is a default. So building :class:`~pcapkit.protocols.application.http.HTTP`
from fields, or calling its ``make``, raises without ``version``; v1.5.1 built
HTTP/1.* by default, and #2544's ``_dispatch_fields`` picked HTTP/2 for a field
only HTTP/2 takes. Its ``from_data`` gives the member whose data model it is
handed and refuses a ``dict``, which v1.5.1 rebuilt by its ``receipt`` or ``sid``
key. Octets dispatch without ``version``, since HTTP octets carry their own;
#2544's module covers that. A member takes ``version`` only as its own, as ICMP's
do.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

#: An HTTP/1.1 request and an HTTP/2 ``DATA`` frame on stream 1.
OCTETS = {
    1: b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n',
    2: bytes.fromhex('000000000000000001'),
}

#: The refusal of fields given no ``version``.
NO_VERSION_FIELDS = '^HTTP: no version to build with; pass version=1 or version=2$'


def fields(version: 'int') -> 'dict[str, object]':
    """Fields only the member of ``version`` takes."""
    from pcapkit.const.http.frame import Frame

    return {'method': 'GET', 'uri': '/'} if version == 1 else {'type': Frame.DATA, 'sid': 1}


class HTTPBaseVersionRuleTests(unittest.TestCase):
    """``version`` alone picks the member; no field, key or default does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def member(version: 'int') -> 'type':
        from pcapkit.protocols.application.httpv1 import HTTPv1
        from pcapkit.protocols.application.httpv2 import HTTPv2

        return {1: HTTPv1, 2: HTTPv2}[version]

    def test_fields_without_version_raise(self) -> None:
        """Even a field only one member takes picks nothing, ``preface`` included."""
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        for label, kwargs in (('no fields', {}), ('HTTP/1 fields', fields(1)),
                              ('HTTP/2 fields', fields(2)), ('preface', {'preface': True}),
                              ('false preface', {'preface': False})):
            with self.subTest(fields=label):
                with self.assertRaisesRegex(ProtocolError, NO_VERSION_FIELDS):
                    HTTP(**kwargs)

    def test_make_has_no_default_version(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        for version in (1, 2):
            with self.subTest(fields=version):
                with self.assertRaisesRegex(ProtocolError, NO_VERSION_FIELDS):
                    HTTP.make(object.__new__(HTTP), **fields(version))  # type: ignore[arg-type]
                schema = HTTP.make(object.__new__(HTTP), version=version, **fields(version))  # type: ignore[arg-type]
                self.assertEqual(schema.pack(), self.member(version)(**fields(version)).data)

    def test_version_is_the_only_check(self) -> None:
        """A bad ``version`` raises on either path; a field the member lacks fails its check."""
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        for version in (0, 3, True, '1', 1.0, 2.0):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^HTTP: invalid version: {version!r}$'):
                    HTTP(version=version, **fields(1))
                with self.assertRaisesRegex(ProtocolError, f'^HTTP: invalid version: {version!r}$'):
                    HTTP(OCTETS[1], version=version)
        with self.assertRaisesRegex(UnsupportedCall, "^HTTPv1: unexpected keyword\\(s\\): 'sid'"):
            HTTP(version=1, sid=1, **fields(1))

    def test_a_member_takes_version_only_as_its_own(self) -> None:
        """Building, ``version`` must name the member; parsing, it is handed on unread."""
        from pcapkit.protocols.application.httpv1 import HTTPv1
        from pcapkit.protocols.data.application.httpv1 import \
            HTTPv1 as Data_HTTPv1
        from pcapkit.protocols.schema.application.httpv1 import \
            HTTPv1 as Schema_HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        class Custom(HTTPv1, schema=Schema_HTTPv1, data=Data_HTTPv1):
            """A subclass of a member, which is that member's version."""

        for version, other in ((1, 2), (2, 1)):
            klass = self.member(version)
            with self.subTest(member=klass.__name__):
                self.assertEqual(klass(version=version, **fields(version)).data,
                                 klass(**fields(version)).data)
                with self.assertRaisesRegex(ProtocolError,
                                            f'^{klass.__name__}: version={other} names another member$'):
                    klass(version=other, **fields(version))
                self.assertEqual(klass(OCTETS[version], version=other).data, OCTETS[version])
        self.assertIs(type(Custom(version=1, **fields(1))), Custom)
        with self.assertRaisesRegex(ProtocolError, '^Custom: version=2 names another member$'):
            Custom(version=2, **fields(1))

    def test_a_subclass_outside_the_members_has_no_version_of_its_own(self) -> None:
        """So it takes no ``version``, as a member takes no other's."""
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        class Outside(HTTP):  # type: ignore[type-arg]
            """A concrete subclass of the base that is no member."""

            @classmethod
            def __index__(cls) -> 'int':  # type: ignore[override]
                raise NotImplementedError

            def read(self, length: 'object' = None, **kwargs: 'object') -> 'object':
                raise NotImplementedError

            def make(self, **kwargs: 'object') -> 'object':
                raise NotImplementedError

        for version in (1, 2):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError,
                                            f'^Outside: no version of its own to match version={version}$'):
                    Outside(version=version)

    def test_http1_refuses_a_preface(self) -> None:
        """``pack`` writes the preface for any member, so HTTP/1 refuses it, built directly too."""
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        for label, build in (('base', lambda: HTTP(version=1, preface=True, **fields(1))),
                             ('member', lambda: self.member(1)(preface=True, **fields(1))),
                             ('make', lambda: HTTP.make(object.__new__(HTTP), version=1,  # type: ignore[arg-type]
                                                        preface=True, **fields(1)))):
            with self.subTest(built=label):
                with self.assertRaisesRegex(ProtocolError, '^HTTP/1: connection preface is HTTP/2 only$'):
                    build()
        self.assertEqual(self.member(1)(preface=False, **fields(1)).data, self.member(1)(**fields(1)).data)

    def test_from_data_dispatches_by_class_and_refuses_a_dict(self) -> None:
        """No key picks a member, though ``receipt`` or ``sid`` would tell them apart."""
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        for version, octets in OCTETS.items():
            with self.subTest(octets=version):
                parsed = self.member(version)(octets)
                rebuilt = HTTP.from_data(parsed.info)
                self.assertIs(type(rebuilt), self.member(version))
                self.assertEqual(rebuilt.data, octets)
                self.assertEqual(self.member(version).from_data(parsed.info.to_dict()).data, octets)
                with self.assertRaisesRegex(ProtocolError,
                                            '^HTTP: invalid data: must be an HTTPv1 or HTTPv2 data model$'):
                    HTTP.from_data(parsed.info.to_dict())

    def test_from_data_takes_version_only_as_the_data_models_own(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        for version, other in ((1, 2), (2, 1)):
            klass = self.member(version)
            with self.subTest(member=klass.__name__):
                info = klass(OCTETS[version]).info
                self.assertEqual(HTTP.from_data(info, version=version).data, OCTETS[version])
                with self.assertRaisesRegex(ProtocolError,
                                            f'^{klass.__name__}: version={other} names another member$'):
                    HTTP.from_data(info, version=other)


if __name__ == '__main__':
    unittest.main()
