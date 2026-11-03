# -*- coding: utf-8 -*-
"""SCTP's enumeration fields take a member or an ``int`` code (GitHub issue #2594).

The owner ruled, in review of #2593 (which closes #2489), that a ``make()`` field
holding an enumeration takes the member or an :class:`int`, resolved with the
enumeration's ``get``, and that nothing inside ``make()`` turns a name into a
member; and on #2617 that a code its field cannot carry, or a ``bool`` for a field
wider than one bit, raises ``ProtocolError``. A code the field carries but no
member holds is written as given, so that a capture of it rebuilds. SCTP's makers
took no ``X_default`` group, so this holds them to the rest of that rule.

Each row of :data:`FIELDS` is one enumeration field of a chunk, parameter or
error cause maker, reached through ``SCTP.make(chunks=...)`` as a caller reaches
it, with its enumeration and the width :rfc:`9260` gives it. The chunk type,
parameter type and cause code that pick a maker are resolved the same way, as
the code of a ``(code, args)`` tuple, so each has a row too; a parsed list given
back to ``make`` has its keys checked as those codes are.

Every case builds its own octets, so this belongs to the unit tier.

"""
from __future__ import annotations

import importlib
import re
import unittest
from typing import TYPE_CHECKING, NamedTuple
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

#: Test tier (#1958): a per-protocol field table.
__tier__ = 'LATEST'


def _data_chunk(value: 'Any') -> 'list':
    """A DATA chunk whose payload protocol identifier is ``value``."""
    from pcapkit.const.sctp.chunk import Chunk

    return [(Chunk.Payload_Data, {'ppid': value, 'data': b'\x01'})]


def _addrtypes_param(value: 'Any') -> 'list':
    """An INIT chunk carrying a supported address types parameter listing ``value``."""
    from pcapkit.const.sctp.chunk import Chunk
    from pcapkit.const.sctp.parameter import Parameter

    return [(Chunk.Initiation, {'parameters': [(Parameter.Supported_Address_Types, {'types': [value]})]})]


def _missing_param_cause(value: 'Any') -> 'list':
    """An ERROR chunk carrying a missing mandatory parameter cause listing ``value``."""
    from pcapkit.const.sctp.cause_code import CauseCode
    from pcapkit.const.sctp.chunk import Chunk

    return [(Chunk.Operation_Error, {'error': [(CauseCode.Missing_Mandatory_Parameter, {'types': [value]})]})]


class Row(NamedTuple):
    """One enumeration field of an SCTP maker."""

    #: The maker the field belongs to.
    maker: 'str'
    #: The field's keyword.
    field: 'str'
    #: The enumeration, as ``module:class``.
    enum: 'str'
    #: The field's width, in bits.
    bits: 'int'
    #: A member to build with.
    member: 'str'
    #: The field's name, as a refusal message ends it.
    name: 'str'
    #: The ``chunks`` argument of ``SCTP.make`` that carries a value for the field.
    chunks: 'Callable[[Any], list]'
    #: The field's value, read off the schema ``SCTP.make`` built.
    built: 'Callable[[Any], Any]'
    #: For a chunk, parameter or cause list, the ``chunks`` argument carrying the
    #: parsed list of a packet's info re-keyed by a value: ``keyed(info, value)``.
    keyed: 'Optional[Callable[[Any, Any], Any]]' = None


def _rekey(items: 'Any', value: 'Any') -> 'Any':
    """The first item of the parsed list ``items``, as the one item of a list keyed by ``value``."""
    from pcapkit.corekit.multidict import OrderedMultiDict

    return OrderedMultiDict([(value, next(iter(items.items(multi=True)))[1])])


def _chunk(value: 'Any') -> 'list':
    """A SHUTDOWN COMPLETE chunk, typed ``value``."""
    return [(value, {})]


def _param(value: 'Any') -> 'list':
    """An INIT chunk carrying a Forward-TSN-Supported parameter, typed ``value``."""
    from pcapkit.const.sctp.chunk import Chunk

    return [(Chunk.Initiation, {'parameters': [(value, {})]})]


def _cause(value: 'Any') -> 'list':
    """An ERROR chunk carrying an out of resource cause, coded ``value``."""
    from pcapkit.const.sctp.chunk import Chunk

    return [(Chunk.Operation_Error, {'error': [(value, {})]})]


def _keyed_param(info: 'Any', value: 'Any') -> 'list':
    """The INIT chunk of ``info``, its parameter list re-keyed by ``value``."""
    from pcapkit.const.sctp.chunk import Chunk

    init = next(iter(info.chunks.items(multi=True)))[1]
    return [(Chunk.Initiation, {'parameters': _rekey(init.parameters, value)})]


def _keyed_cause(info: 'Any', value: 'Any') -> 'list':
    """The ERROR chunk of ``info``, its cause list re-keyed by ``value``."""
    from pcapkit.const.sctp.chunk import Chunk

    error = next(iter(info.chunks.items(multi=True)))[1]
    return [(Chunk.Operation_Error, {'error': _rekey(error.error, value)})]


#: Every enumeration field of SCTP's chunk, parameter and error cause makers.
#: Widths from :rfc:`9260`: Payload Protocol Identifier 32 bits (section 3.3.1),
#: Address Type 16 bits (section 3.3.2.1.5), Missing Param Type 16 bits
#: (section 3.3.10.2), Chunk Type 8 bits (section 3.2), Parameter Type 16 bits
#: (section 3.2.1) and Cause Code 16 bits (section 3.3.10), as the schema's
#: ``EnumField`` lengths agree.
FIELDS = (
    Row('_make_chunk_data', 'ppid',
        'pcapkit.const.sctp.payload_protocol_identifier:PayloadProtocolIdentifier', 32,
        'PayloadProtocolIdentifier_3GPP_NG_Application_Protocol', 'ppid',
        _data_chunk, lambda schema: schema.chunks[0].ppid),
    Row('_make_param_addrtypes', 'types',
        'pcapkit.const.sctp.parameter:Parameter', 16, 'IPv4_Address', 'parameter type',
        _addrtypes_param, lambda schema: schema.chunks[0].parameters[0].types[0]),
    Row('_make_cause_missing_param', 'types',
        'pcapkit.const.sctp.parameter:Parameter', 16, 'State_Cookie', 'parameter type',
        _missing_param_cause, lambda schema: schema.chunks[0].error[0].types[0]),
    Row('_make_sctp_chunks', 'type', 'pcapkit.const.sctp.chunk:Chunk', 8, 'Shutdown_Complete', 'chunk type',
        _chunk, lambda schema: schema.chunks[0].type, lambda info, value: _rekey(info.chunks, value)),
    Row('_make_sctp_parameters', 'type', 'pcapkit.const.sctp.parameter:Parameter', 16, 'Forward_TSN_supported',
        'parameter type', _param, lambda schema: schema.chunks[0].parameters[0].type, _keyed_param),
    Row('_make_sctp_causes', 'code', 'pcapkit.const.sctp.cause_code:CauseCode', 16, 'Out_of_Resource',
        'cause code', _cause, lambda schema: schema.chunks[0].error[0].code, _keyed_cause),
)


class SCTPMakeCodeTests(unittest.TestCase):
    """Each row refuses what its field cannot carry, and resolves a code with ``get``."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    @staticmethod
    def _enum(row: 'Row') -> 'Any':
        module, name = row.enum.split(':')
        return getattr(importlib.import_module(module), name)

    @staticmethod
    def _make(row: 'Row', value: 'Any', chunks: 'Any' = None) -> 'Any':
        """The schema ``SCTP.make`` builds with ``value`` for the row's field, or from ``chunks``."""
        from pcapkit.protocols.transport.sctp import SCTP

        proto = SCTP.__new__(SCTP)
        return SCTP.make(proto, srcport=9899, dstport=38412, chksum=b'\x00' * 4,
                         chunks=row.chunks(value) if chunks is None else chunks)

    def assertRefused(self, row: 'Row', value: 'Any', chunks: 'Any' = None) -> 'None':
        """Building with ``value``, or from ``chunks``, raises ``ProtocolError`` naming the field."""
        from pcapkit.utilities.exceptions import ProtocolError

        try:
            self._make(row, value, chunks)
        except ProtocolError as error:
            self.assertRegex(str(error), rf'^SCTP: invalid (.* )?{re.escape(row.name)}: {re.escape(repr(value))}$')
        except Exception as error:  # pylint: disable=broad-except
            self.fail(f'{row.maker} {row.field}={value!r} raised {type(error).__name__}, not ProtocolError: {error}')
        else:
            self.fail(f'{row.maker} {row.field}={value!r} was accepted')

    def test_each_row_reaches_its_maker(self) -> 'None':
        from pcapkit.protocols.transport.sctp import SCTP

        for row in FIELDS:
            member = getattr(self._enum(row), row.member)
            with self.subTest(maker=row.maker), \
                    mock.patch.object(SCTP, row.maker, autospec=True, side_effect=getattr(SCTP, row.maker)) as maker:
                self._make(row, member)
                self.assertTrue(maker.called)

    def test_code_wider_than_the_field_is_refused(self) -> 'None':
        for row in FIELDS:
            with self.subTest(maker=row.maker, field=row.field):
                self.assertRefused(row, 1 << row.bits)

    def test_negative_code_is_refused(self) -> 'None':
        for row in FIELDS:
            with self.subTest(maker=row.maker, field=row.field):
                self.assertRefused(row, -1)

    def test_bool_is_refused(self) -> 'None':
        for row in FIELDS:
            self.assertGreater(row.bits, 1)
            with self.subTest(maker=row.maker, field=row.field):
                self.assertRefused(row, True)

    def test_name_is_refused(self) -> 'None':
        for row in FIELDS:
            with self.subTest(maker=row.maker, field=row.field):
                self.assertRefused(row, row.member)

    def test_member_and_code_build_identical_octets(self) -> 'None':
        for row in FIELDS:
            member = getattr(self._enum(row), row.member)
            with self.subTest(maker=row.maker, field=row.field):
                self.assertEqual(self._make(row, member).pack(), self._make(row, int(member)).pack())

    def test_code_resolves_to_its_member(self) -> 'None':
        for row in FIELDS:
            member = getattr(self._enum(row), row.member)
            with self.subTest(maker=row.maker, field=row.field):
                self.assertIs(row.built(self._make(row, int(member))), member)

    def test_a_parsed_list_has_its_keys_checked(self) -> 'None':
        """A parsed list rebuilds as it was, and one keyed by a refused code is refused."""
        from pcapkit.protocols.transport.sctp import SCTP

        for row in FIELDS:
            if row.keyed is None:
                continue
            member = getattr(self._enum(row), row.member)
            octets = self._make(row, member).pack()
            info = SCTP(octets, len(octets)).info
            with self.subTest(maker=row.maker):
                self.assertEqual(self._make(row, member, row.keyed(info, member)).pack(), octets)
                for value in (1 << row.bits, -1, True, row.member):
                    self.assertRefused(row, value, row.keyed(info, value))

    def test_code_no_member_holds_is_written_as_given(self) -> 'None':
        """A code the field carries but no member holds builds, and its capture
        rebuilds byte for byte."""
        from pcapkit.protocols.transport.sctp import SCTP

        memberless = {}  # type: dict[str, list[int]]
        for row in FIELDS:
            with self.subTest(maker=row.maker, field=row.field):
                if row.bits > 16:
                    self.skipTest('too wide to search for a code no member holds')
                if row.enum not in memberless:
                    enum = self._enum(row)
                    codes = []
                    for code in range(1 << row.bits):
                        try:
                            enum.get(code)
                        except ValueError:
                            codes.append(code)
                    memberless[row.enum] = codes
                if not memberless[row.enum]:
                    self.skipTest(f'a member holds every {row.bits}-bit code of {row.enum}')
                for code in memberless[row.enum]:
                    try:
                        schema = self._make(row, code)
                    except Exception as error:  # pylint: disable=broad-except
                        self.fail(f'{row.maker} {row.field}={code!r} raised {type(error).__name__}: {error}')
                    self.assertEqual(int(row.built(schema)), code)
                    octets = schema.pack()
                    parsed = SCTP(octets, len(octets))
                    proto = SCTP.__new__(SCTP)
                    rebuilt = SCTP.make(proto, srcport=9899, dstport=38412, chksum=b'\x00' * 4,
                                        chunks=parsed.info.chunks)
                    self.assertEqual(rebuilt.pack(), octets)


if __name__ == '__main__':
    unittest.main()
