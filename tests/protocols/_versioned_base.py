# -*- coding: utf-8 -*-
"""The versioned-family contract the base-dispatch modules share. C.f. #2574.

A versioned family's base never yields an instance of itself: it dispatches to the
member on parse and on make (#2544), and ``version`` alone names the member -- no
field picks one and no member is a default (#2574). Each family module builds its
test case on the mixins its base's shape takes, and sets the tables they read:

* :class:`VersionedBase`, for every family: ``version`` through the base, a member,
  a subclass of a member and a subclass outside the members;
* :class:`OctetsCarryNoVersion` or :class:`OctetsCarryTheVersion`: whether the base
  refuses octets without ``version``, or reads their member off them;
* :class:`FromDataByModel` or :class:`FromDataByVersion`: whether the base's
  ``from_data`` reads the data model's class, or its ``version``.

The mixins are plain classes, so only a family module's test case is collected.
Nothing here imports :mod:`pcapkit` at module level: classes are named as
``module:Class`` and resolved inside each test, after
:func:`~tests._support.reimport_once_per_class`, and a table that may hold a
:mod:`pcapkit` object is a method for that reason. Shared under #3148.

"""
from __future__ import annotations

import enum
import importlib
import io
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Optional

    # NOTE: A test case to the type checker alone, so that the mixins stay plain.
    _Case = unittest.TestCase
else:
    _Case = object

#: How a test hands octets over: as :obj:`bytes`, or as a stream and its length.
SOURCES = ('bytes', 'stream')


def resolve(path: 'str') -> 'Any':
    """Import ``module:Class`` from the current :mod:`pcapkit` import."""
    module, _, name = path.partition(':')
    return getattr(importlib.import_module(module), name)


def parse(klass: 'Any', octets: 'bytes', source: 'str', **kwargs: 'Any') -> 'Any':
    """``klass`` over ``octets``, handed over as ``source`` names."""
    if source == 'bytes':
        return klass(octets, **kwargs)
    return klass(io.BytesIO(octets), len(octets), **kwargs)


class VersionedBase(_Case):
    """``version`` names the member on every path, and nothing else does."""

    #: The family base, as ``module:Class``.
    BASE = ''
    #: Each member, as ``module:Class``, by the ``version`` that names it.
    MEMBERS = {}  # type: dict[int, str]
    #: Octets by label, with the ``version`` of the member they are; a member's
    #: first entry is the one its own checks parse.
    OCTETS = {}  # type: dict[str, tuple[bytes, int]]
    #: ``version`` values no member answers to, wrong in value or in type.
    BAD_VERSIONS = ()  # type: tuple[object, ...]
    #: The ``version`` of the member a custom subclass derives from, that member's
    #: schema and data model as ``module:Class``, and fields to build both with.
    CUSTOM = (0, '', '', {})  # type: tuple[int, str, str, dict[str, Any]]
    #: Whether the base is abstract; a direct subclass of a concrete one parses as
    #: itself.
    ABSTRACT = True
    #: Whether ``version`` is a field the member's ``make`` writes, as L2TPv2's is,
    #: so that a subclass outside the members is refused it only when parsing.
    VERSION_IS_A_FIELD = False

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def fields(self, version: 'int') -> 'dict[str, Any]':  # pylint: disable=unused-argument
        """Fields a build of the member of ``version`` is given where a check names none."""
        return {}

    def cases_from_fields(self) -> 'dict[str, tuple[dict[str, Any], int, Optional[bytes]]]':
        """Fields by label, with the ``version`` building them and the octets, if pinned."""
        return {}

    def versionless_fields(self) -> 'dict[str, dict[str, Any]]':
        """Fields by label that pick no member without ``version``."""
        return {}

    def foreign_fields(self) -> 'dict[int, dict[str, Any]]':
        """By ``version``, one field the member of that version does not take."""
        return {}

    @property
    def name(self) -> 'str':
        """The base's class name, as its messages spell it."""
        return self.BASE.rpartition(':')[2]

    @property
    def versions(self) -> 'str':
        """The ``version`` keywords the base's refusals ask for."""
        return ' or '.join(f'version={version}' for version in self.MEMBERS)

    def base(self) -> 'Any':
        return resolve(self.BASE)

    def member(self, version: 'int') -> 'Any':
        return resolve(self.MEMBERS[version])

    def own_octets(self, version: 'int') -> 'bytes':
        return next(octets for octets, of in self.OCTETS.values() if of == version)

    def others(self, version: 'int') -> 'list[int]':
        return [other for other in self.MEMBERS if other != version]

    def parse_back(self, octets: 'bytes', version: 'int') -> 'Any':
        """``octets`` parsed through the base, as a build of ``version`` is read back."""
        return self.base()(octets, version=version)

    def test_fields_without_version_raise(self) -> None:
        """Even a field only one member takes picks nothing."""
        from pcapkit.utilities.exceptions import ProtocolError

        base = self.base()
        for label, fields in self.versionless_fields().items():
            with self.subTest(fields=label):
                with self.assertRaisesRegex(
                        ProtocolError, f'^{self.name}: no version to build with; pass {self.versions}$'):
                    base.from_fields(**fields)

    def test_version_picks_the_member_from_fields(self) -> None:
        """Each build is byte-exact against the member's own and parses back unchanged."""
        base = self.base()
        for label, (fields, version, octets) in self.cases_from_fields().items():
            member = self.member(version)
            with self.subTest(fields=label):
                layer = base.from_fields(version=version, **fields)
                self.assertIs(type(layer), member)
                self.assertEqual(layer.data, member.from_fields(**fields).data)
                self.assertEqual(layer.data, member.from_fields(version=version, **fields).data)
                if octets is not None:
                    self.assertEqual(layer.data, octets)
                parsed = self.parse_back(layer.data, version)
                self.assertIs(type(parsed), member)
                self.assertEqual(parsed.data, layer.data)
                self.assertEqual(base.from_data(parsed.info).data, layer.data)

    def test_version_is_the_only_check(self) -> None:
        """A bad ``version`` raises on either path; a field the member lacks fails the member's check.

        An :class:`~enum.IntEnum` member is an :obj:`int`, and accepted.

        """
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        base = self.base()
        octets = next(iter(self.OCTETS.values()))[0]
        for version in self.BAD_VERSIONS:
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^{self.name}: invalid version: {version!r}$'):
                    base.from_fields(version=version, **self.fields(min(self.MEMBERS)))
                with self.assertRaisesRegex(ProtocolError, f'^{self.name}: invalid version: {version!r}$'):
                    base(octets, version=version)
        for version in self.MEMBERS:
            member = enum.IntEnum('Version', {'MEMBER': version}).MEMBER
            self.assertIs(type(base.from_fields(version=member, **self.fields(version))),
                          self.member(version))
        for version, foreign in self.foreign_fields().items():
            (keyword,) = foreign
            with self.assertRaisesRegex(
                    UnsupportedCall, f"^{self.member(version).__name__}: unexpected keyword\\(s\\): '{keyword}'"):
                base.from_fields(version=version, **self.fields(version), **foreign)

    def test_a_member_takes_version_only_as_its_own(self) -> None:
        """Building, parsing or rebuilding through the base, ``version`` must name the member (#2840)."""
        from pcapkit.utilities.exceptions import ProtocolError

        base = self.base()
        for version in self.MEMBERS:
            member, octets, fields = self.member(version), self.own_octets(version), self.fields(version)
            with self.subTest(member=member.__name__):
                self.assertEqual(member.from_fields(version=version, **fields).data,
                                 member.from_fields(**fields).data)
                parsed = member(octets, version=version)
                self.assertIs(type(parsed), member)
                self.assertEqual(parsed.data, octets)
                self.assertEqual(base.from_data(parsed.info, version=version).data, octets)
                for other in self.others(version):
                    message = f'^{member.__name__}: version={other} names another member$'
                    with self.assertRaisesRegex(ProtocolError, message):
                        member.from_fields(version=other, **fields)
                    with self.assertRaisesRegex(ProtocolError, message):
                        member(octets, version=other)
                    with self.assertRaisesRegex(ProtocolError, message):
                        base.from_data(parsed.info, version=other)

    def test_a_subclass_outside_the_members_has_no_version_of_its_own(self) -> None:
        """So it takes no ``version``, as a member takes no other's."""
        from pcapkit.utilities.exceptions import ProtocolError

        class Outside(self.base()):  # type: ignore[misc]
            """A concrete subclass of the base that is no member."""

            name = length = None
            @classmethod
            def __index__(cls) -> 'int':
                raise NotImplementedError

            def read(self, length: 'object' = None, **kwargs: 'object') -> 'object':
                raise NotImplementedError

            def make(self, **kwargs: 'object') -> 'object':
                raise NotImplementedError

        for version in self.MEMBERS:
            with self.subTest(version=version):
                message = f'^Outside: no version of its own to match version={version}$'
                with self.assertRaisesRegex(ProtocolError, message):
                    Outside(self.own_octets(version), version=version)
                if not self.VERSION_IS_A_FIELD:
                    with self.assertRaisesRegex(ProtocolError, message):
                        Outside.from_fields(version=version)

    def test_only_the_base_dispatches(self) -> None:
        """A subclass of the base is constructed as itself, abstract or not.

        A subclass of a member is that member's version.

        """
        from pcapkit.utilities.exceptions import ProtocolError

        base = self.base()
        version, schema, data, fields = self.CUSTOM
        member, octets = self.member(version), self.own_octets(version)

        class Direct(base):  # type: ignore[misc] # pylint: disable=abstract-method
            """A direct subclass of the base."""

        class Custom(member, schema=resolve(schema), data=resolve(data)):  # type: ignore[misc]
            """A concrete subclass of the base, through a member."""

        self.assertIs(type(base.from_fields(version=version, **fields)), member)
        self.assertIs(type(Custom(octets)), Custom)
        self.assertIs(type(Custom.from_fields(**fields)), Custom)
        self.assertIs(type(Custom.from_fields(version=version, **fields)), Custom)
        self.assertIs(type(Custom.from_data(Custom(octets).info)), Custom)
        for other in self.others(version):
            with self.assertRaisesRegex(ProtocolError, f'^Custom: version={other} names another member$'):
                Custom.from_fields(version=other, **fields)
        if self.ABSTRACT:
            with self.assertRaisesRegex(TypeError, 'abstract'):
                Direct(octets)
        else:
            self.assertIs(type(Direct(octets)), Direct)


class OctetsCarryNoVersion(VersionedBase):
    """The octets carry no version: the base refuses them without ``version``, and parses any with it."""

    def test_octets_without_version_raise(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        names = ' or '.join(path.rpartition(':')[2] for path in self.MEMBERS.values())
        message = f'^{self.name}: no version field; pass {self.versions}, or parse with {names}$'
        for label, (octets, _) in self.OCTETS.items():
            for source in SOURCES:
                with self.subTest(octets=label, source=source):
                    with self.assertRaisesRegex(ProtocolError, message):
                        parse(self.base(), octets, source)

    def test_version_picks_the_member_from_octets(self) -> None:
        """Even octets of the other version: the format carries none to object."""
        base = self.base()
        for version in self.MEMBERS:
            member = self.member(version)
            for label, (octets, _) in self.OCTETS.items():
                direct = member(octets)
                for source in SOURCES:
                    with self.subTest(version=version, octets=label, source=source):
                        layer = parse(base, octets, source, version=version)
                        self.assertIs(type(layer), member)
                        self.assertIsInstance(layer, base)
                        self.assertEqual(layer.data, octets)
                        self.assertEqual(layer.data, direct.data)
                        self.assertEqual(str(layer.protochain), str(direct.protochain))


class OctetsCarryTheVersion(VersionedBase):
    """The octets carry their version: the base reads it, and the member refuses another's."""

    #: Octets by the version they carry, which no member reads.
    NO_MEMBER = {}  # type: dict[int, bytes]
    #: Octets too short to carry a version, and the base's refusal of them.
    SHORT = (b'', '')
    #: Octets by label, with a ``version`` naming another member, and that
    #: member's refusal as a pattern.
    CROSSED = {}  # type: dict[str, tuple[bytes, int, str]]

    def parse_back(self, octets: 'bytes', version: 'int') -> 'Any':
        """``octets`` parsed through the base without ``version``, as they carry it."""
        return self.base()(octets)

    def test_octets_give_the_member_their_version_names(self) -> None:
        """Without ``version`` or with the one they carry, as the member would parse them."""
        base = self.base()
        for label, (octets, version) in self.OCTETS.items():
            member = self.member(version)
            direct = member(octets)
            for source in SOURCES:
                with self.subTest(octets=label, source=source):
                    layer = parse(base, octets, source)
                    self.assertIs(type(layer), member)
                    self.assertIsInstance(layer, base)
                    self.assertEqual(layer.info.version, version)
                    self.assertEqual(layer.data, octets)
                    self.assertEqual(str(layer.protochain), str(direct.protochain))
                    named = parse(base, octets, source, version=version)
                    self.assertIs(type(named), member)
                    self.assertEqual(named.data, octets)

    def test_octets_naming_no_member_raise(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        base = self.base()
        for version, octets in self.NO_MEMBER.items():
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^{self.name}: invalid version: {version}$'):
                    base(octets)
        octets, refusal = self.SHORT
        with self.assertRaisesRegex(ProtocolError, f'^{self.name}: {refusal}$'):
            base(octets)

    def test_version_over_octets_of_another_version_is_the_parser_s_error(self) -> None:
        """No cross-check: the member ``version`` names parses, and refuses the version field."""
        from pcapkit.utilities.exceptions import ProtocolError

        for label, (octets, version, refusal) in self.CROSSED.items():
            with self.subTest(case=label):
                with self.assertRaisesRegex(ProtocolError, refusal):
                    self.base()(octets, version=version)


class FromDataByModel(VersionedBase):
    """The base's ``from_data`` gives the member whose data model it is handed, and refuses a :obj:`dict`."""

    #: The refusal of a :obj:`dict`, as a pattern.
    NOT_A_DATA_MODEL = ''

    def test_from_data_on_the_base_gives_the_member(self) -> None:
        """No key picks a member, though a member rebuilds from its own :obj:`dict`."""
        from pcapkit.utilities.exceptions import ProtocolError

        base = self.base()
        for label, (octets, version) in self.OCTETS.items():
            member = self.member(version)
            parsed = member(octets)
            with self.subTest(octets=label):
                rebuilt = base.from_data(parsed.info)
                self.assertIs(type(rebuilt), member)
                self.assertEqual(rebuilt.data, octets)
                self.assertEqual(member.from_data(parsed.info.to_dict()).data, octets)
                with self.assertRaisesRegex(ProtocolError, self.NOT_A_DATA_MODEL):
                    base.from_data(parsed.info.to_dict())


class FromDataByVersion(VersionedBase):
    """The base's ``from_data`` gives the member the data's ``version`` names, a :obj:`dict`'s too."""

    def test_from_data_on_the_base_gives_the_member(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        base = self.base()
        for label, (octets, version) in self.OCTETS.items():
            parsed = self.member(version)(octets)
            for form in ('info', 'dict'):
                with self.subTest(octets=label, form=form):
                    rebuilt = base.from_data(parsed.info if form == 'info' else parsed.info.to_dict())
                    self.assertIs(type(rebuilt), self.member(version))
                    self.assertEqual(rebuilt.data, octets)
        for data in ({}, *({'version': version} for version in self.BAD_VERSIONS)):
            with self.subTest(data=data):
                with self.assertRaisesRegex(
                        ProtocolError, f"^{self.name}: invalid version: {data.get('version')!r}$"):
                    base.from_data(data)
