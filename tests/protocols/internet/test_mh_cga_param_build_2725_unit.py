# -*- coding: utf-8 -*-
"""An MH CGA parameter builds from a data model with a raw extension, or a schema without its key test.

GitHub issue #2725 found two defects in building the CGA Parameters option.

- ``make()`` keeps the header it made unless ``_passes_raw`` in
  :mod:`pcapkit.protocols.protocol` finds a raw item among its keywords.
  Missing one inside a data model -- a CGA parameter's, given directly or
  inside the packet's own data model as
  :meth:`~pcapkit.protocols.protocol.Protocol.from_data` passes it -- left the
  octets in the made header, where ``_read_cga_extensions`` raised a bare
  ``AttributeError``. ``_passes_raw`` looks inside a data model, and through
  every value of a multi-mapping, so a raw extension in a later CGA Parameters
  option is found as well.
- ``_make_opt_cga_param`` set ``public_key_test`` on a schema only when
  ``hasattr`` said it was missing. A schema does not store an unset field, so
  ``hasattr`` found the class's field object, and packing raised
  ``KeyError: 'public_key_test'``. The key test goes on a copy, and the
  caller's schema is left as given.

Each build is held to the one a ``(type, kwargs)`` extension or a data model
gives, and to the specification: a CGA Parameters option's Option Length counts
the parameters it carries [:rfc:`4866#section-5.1`], which are the 25 octets of
modifier, subnet prefix and collision count, the public key, and the extensions
[:rfc:`3972#section-3`], each its 4-octet type and length and its data
[:rfc:`4581#section-2`].

Every case builds its own octets in memory and reads no capture. :class:`MH`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: A CGA extension of the unassigned type 1, carrying ``ab``.
EXTENSION = b'\x00\x01\x00\x02ab'
#: The same extension as a ``(type, kwargs)`` pair.
PAIR = (1, {'data': b'ab'})
#: A public key whose DER length is the short form.
SHORT_KEY = b'\x30\x02\xaa\xbb'
#: A public key whose DER length takes the long form, ``0x81`` and one octet.
LONG_KEY = b'\x30\x81\xc8' + bytes(0xc8)
#: The octets of the fixed MH header and of a Binding Refresh Request.
HEADER = 8
#: The octets of a CGA parameter before its public key.
FIXED = 25


def _build(options: 'list[Any]') -> 'Any':
    """A Binding Refresh Request carrying ``options``."""
    from pcapkit.const.mh.packet import Packet
    from pcapkit.protocols.internet.mh.protocol import MH

    return MH(type=Packet.Binding_Refresh_Request, next=59, chksum=b'\x00\x00',
              data={'options': options})


def _fields(key: 'bytes') -> 'dict[str, Any]':
    """The fields of one CGA parameter carrying ``key``, but its extensions."""
    from pcapkit.const.mh.cga_type import CGAType

    return {
        'modifier': CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
        'prefix': 0x20010db800000000,
        'collision_count': 0,
        'public_key': key,
    }


def _option(parameters: 'list[Any]') -> 'tuple[Any, dict[str, Any]]':
    """A CGA Parameters option carrying ``parameters``, as a ``(type, kwargs)`` pair."""
    from pcapkit.const.mh.option import Option

    return (Option.CGA_Parameters, {'parameters': parameters})


def _with_raw(info: 'Any') -> 'Any':
    """``info`` with each CGA parameter's extensions given as the raw :data:`EXTENSION`."""
    from pcapkit.const.mh.option import Option
    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.internet.mh.data import CGAParameter, CGAParametersOption

    dict_ = info.to_dict()
    options = OrderedMultiDict()  # type: OrderedMultiDict[Any, Any]
    for code, option in dict_['options'].items(multi=True):
        if code == Option.CGA_Parameters and option.parameters:
            option = CGAParametersOption(type=option.type, length=option.length, parameters=tuple(
                CGAParameter(extensions=[EXTENSION], **_fields(param.public_key))
                for param in option.parameters))
        options.add(code, option)
    dict_['options'] = options
    return type(info).from_dict(dict_)


class _Case(unittest.TestCase):
    """Shared assertions."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertCGAOption(self, data: 'bytes', key: 'bytes', extensions: 'bytes') -> None:
        """The first option of ``data`` is a CGA Parameters option of one parameter."""
        from pcapkit.const.mh.option import Option

        self.assertEqual(data[HEADER], Option.CGA_Parameters)
        self.assertEqual(data[HEADER + 1], FIXED + len(key) + len(extensions))
        start = HEADER + 2 + FIXED
        self.assertEqual(data[start:start + len(key)], key)
        end = start + len(key) + len(extensions)
        self.assertEqual(data[start + len(key):end], extensions)


class TestMHCGARawExtensionInDataModel(_Case):
    """A CGA parameter's data model holding a raw extension builds as its pair does."""

    def test_data_model_builds_as_its_pair(self) -> None:
        from pcapkit.protocols.internet.mh.data import CGAParameter

        for key in (SHORT_KEY, LONG_KEY):
            with self.subTest(key=len(key)):
                raw = _build([_option([CGAParameter(extensions=[EXTENSION], **_fields(key))])])
                pair = _build([_option([CGAParameter(extensions=[PAIR], **_fields(key))])])
                self.assertEqual(raw.data, pair.data)
                self.assertCGAOption(raw.data, key, EXTENSION)

    def test_from_data_rebuilds_a_raw_extension(self) -> None:
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh.data import CGAParameter
        from pcapkit.protocols.internet.mh.protocol import MH

        cases = {
            'one option': [_option([CGAParameter(extensions=[PAIR], **_fields(SHORT_KEY))])],
            # NOTE: The parameters may span several options (RFC 4866, section
            # 5.1); a multi-mapping's first value per key hides the second.
            'a later option': [
                _option([]),
                _option([CGAParameter(extensions=[PAIR], **_fields(LONG_KEY))]),
            ],
        }
        for label, options in cases.items():
            expected = _build(options)
            info = _with_raw(expected.info)
            for source, data in (('info', info), ('to_dict', info.to_dict())):
                with self.subTest(case=label, source=source):
                    rebuilt = MH.from_data(data)
                    self.assertEqual(rebuilt.data, expected.data)
                    (*_, option) = rebuilt.info.options.getlist(Option.CGA_Parameters)
                    (param,) = option.parameters
                    (extension,) = param.extensions.getlist(CGAExtension.get(1))
                    self.assertEqual(extension.data, b'ab')
                    self.assertEqual(extension.length, len(EXTENSION))


class TestMHCGASchemaWithoutKeyTest(_Case):
    """A CGA parameter schema without ``public_key_test`` builds as its data model does."""

    def test_schema_builds_as_its_data_model(self) -> None:
        from pcapkit.protocols.internet.mh.data import CGAParameter
        from pcapkit.protocols.internet.mh.schema import CGAParameter as Schema_CGAParameter

        for key in (SHORT_KEY, LONG_KEY):
            for extensions, pairs in (([], []), ([EXTENSION], [PAIR])):
                with self.subTest(key=len(key), extensions=extensions):
                    schema = Schema_CGAParameter(extensions=extensions, **_fields(key))
                    built = _build([_option([schema])])
                    model = _build([_option([CGAParameter(extensions=pairs, **_fields(key))])])
                    self.assertEqual(built.data, model.data)
                    self.assertCGAOption(built.data, key, b''.join(extensions))
                    self.assertNotIn('public_key_test', schema)

    def test_schema_without_key_test_round_trips(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.protocols.internet.mh.schema import CGAParameter as Schema_CGAParameter

        for key in (SHORT_KEY, LONG_KEY):
            with self.subTest(key=len(key)):
                built = _build([_option([Schema_CGAParameter(extensions=[EXTENSION], **_fields(key))])])
                parsed = MH(built.data)
                (option,) = parsed.info.options.getlist(Option.CGA_Parameters)
                (param,) = option.parameters
                self.assertEqual(param.public_key, key)
                self.assertEqual(MH.from_data(parsed.info).data, built.data)


if __name__ == '__main__':
    unittest.main()
