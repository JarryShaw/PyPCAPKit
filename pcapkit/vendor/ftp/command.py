# -*- coding: utf-8 -*-
"""FTP Command
=================

.. module:: pcapkit.vendor.ftp.command

This module contains the vendor crawler for **FTP Command**,
which is automatically generating :class:`pcapkit.const.ftp.command.Command`.

"""
import collections
import csv
import re
import sys
from typing import TYPE_CHECKING, cast

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import OrderedDict
    from typing import Callable

__all__ = ['Command']

#: Command type.
KIND = {
    'a': 'CommandType.A',
    'p': 'CommandType.P',
    's': 'CommandType.S',
}  # type: dict[str, str]

#: Conformance requirements.
CONF = {
    'm': 'ConformanceRequirement.M',
    'o': 'ConformanceRequirement.O',
    'h': 'ConformanceRequirement.H',
}  # type: dict[str, str]

#: Default constant template of enumerate registry from IANA CSV.
LINE = lambda NAME, DOCS, ENUM, FEAT, MODL: f'''\
# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum, IntFlag, StrEnum, auto

from pcapkit.corekit.enum import EnumRegistry

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['{NAME}']


class FEATCode(EnumRegistry, StrEnum):
    """Keyword returned in FEAT response line for this command/extension,
    c.f., :rfc:`5797#secion-3`.

    .. note::

       Declares every FEAT keyword the IANA registry's own ``FEAT code``
       column names -- the 5 group markers below plus the per-command
       keywords generated after them (data-driven, not hand-picked; see
       :meth:`~pcapkit.vendor.ftp.command.Command.process`) -- rather than
       minting the per-command ones at import time as an incidental side
       effect of building :class:`Command`'s own rows. GitHub issue #860:
       that import-time mutation was the same defect shape #861 removed
       from :class:`~pcapkit.const.pcapng.filter_type.FilterType`, just not
       previously noticed here. ``_missing_`` still unmints for a keyword
       that turns up on the wire but names none of these -- the
       extendability the owner asked to keep, verbatim: *"If it is expected
       to be handled as our current approach in industry convention, then
       we keep it extendable as is."* No custom ``__new__`` here, so the
       base's generic :meth:`~pcapkit.corekit.enum.EnumRegistry.
       _unregistered_member` needs no override.

    """

    #: FTP standard commands [:rfc:`0959`].
    base = '<base>'
    #: Historic experimental commands [:rfc:`0775`][:rfc:`1639`].
    hist = '<hist>'
    #: FTP Security Extensions [:rfc:`2228`].
    secu = '<secu>'
    #: FTP Feature Negotiation [:rfc:`2389`].
    feat = '<feat>'
    #: FTP Extensions for NAT/IPv6 [:rfc:`2428`].
    nat6 = '<nat6>'

    {FEAT}

    def __repr__(self) -> 'str':
        return f'<{{self.__class__.__name__}} [{{self._name_}}]>'

    @classmethod
    def _missing_(cls, value: 'str') -> 'FEATCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not isinstance(value, str):
            raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')
        return cls._unregistered_member(value, value.upper())


class CommandType(IntFlag):
    """Type of "kind" of command, based on :rfc:`959#section-4.1`."""

    undefined = 0

    #: Access control.
    A = auto()
    #: Parameter setting.
    P = auto()
    #: Service execution.
    S = auto()

    @classmethod
    def _missing_(cls, value: 'int') -> 'CommandType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0x07):
            raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')
        return super()._missing_(value)


class ConformanceRequirement(IntEnum):
    """Expectation for support in modern FTP implementations."""

    #: Mandatory to implement.
    M = auto()
    #: Optional.
    O = auto()
    #: Historic.
    H = auto()


class {NAME}(EnumRegistry, StrEnum):
    """[{NAME}] {DOCS}

    .. note::

       Neither ``_missing_`` nor ``get()`` mints any more, per the owner's
       ruling on GitHub issue #860: *"only IANA registered ones are legit
       values and we need register to properly create new entries. get will
       not have sufficient information to create new ones."* Concretely
       true here -- a bare wire command word carries no
       :attr:`feat`/:attr:`desc`/:attr:`type`/:attr:`conf`, so minting one
       used to register a permanent member with all four hollowed out to
       their defaults; :meth:`register` is the path that can actually supply
       them.

    """

    if TYPE_CHECKING:
        #: Feature code. Keyword returned in FEAT response line for this command/extension,
        #: c.f., :rfc:`5797#secion-2.2`.
        feat: 'Optional[FEATCode]'
        #: Brief description of command / extension.
        desc: 'Optional[str]'
        #: Type of "kind" of command, based on :rfc:`959#section-4.1`.
        type: 'CommandType'
        #: Expectation for support in modern FTP implementations.
        conf: 'ConformanceRequirement'

    def __new__(cls, name: 'str', feat: 'Optional[FEATCode]' = None,
                desc: 'Optional[str]' = None, type: 'CommandType' = CommandType.undefined,
                conf: 'ConformanceRequirement' = ConformanceRequirement.O) -> 'Type[{NAME}]':
        obj = str.__new__(cls, name)
        obj._value_ = name

        obj.feat = feat
        obj.desc = desc
        obj.type = type
        obj.conf = conf

        return obj

    def __repr__(self) -> 'str':
        return f'<{{self.__class__.__name__}}.{{self._name_}}: {{self.desc}}>'

    {ENUM}

    @classmethod
    def _unregistered_member(cls, value: 'str', name: 'str') -> '{NAME}':
        """Build a member absent from this registry's own lookup tables.

        Leaves :attr:`feat`, :attr:`desc`, :attr:`type` and :attr:`conf` at
        the same defaults :meth:`__new__` itself would, rather than missing
        entirely -- :meth:`~pcapkit.corekit.enum.EnumRegistry.
        _unregistered_member` bypasses :meth:`__new__` (it calls
        :class:`str`'s directly), so those four attributes would otherwise
        be absent and :meth:`__repr__` (which reads :attr:`desc`) would
        raise on the result. There is no more specific value to reconstruct
        them from -- a bare wire command word carries none of the four,
        which is exactly the owner's reasoning for why ``get()``/
        ``_missing_`` must not mint one: :meth:`register` is the path that
        can actually supply them.

        Args:
            value: Value to get enum item -- the convention here, shared with
                :class:`~pcapkit.const.ftp.command.FEATCode` and
                :class:`~pcapkit.const.http.method.Method`, is the caller's
                own casing, unchanged: an unregistered member's *value* is
                exactly what was observed on the wire, matching how a
                *registered* member's own value is exactly what was
                declared, never reformatted. Only :attr:`name` -- the
                identifier, not the value -- is canonicalised.
            name: Bare label for the unregistered member -- here, the
                canonical upper-case form of ``value``, matching the name
                every *registered* member of this class is looked up by,
                since #860's open-vocabulary registries have no manufactured
                placeholder label to fall back to.

        """
        obj = super()._unregistered_member(value, name)
        obj.feat = None
        obj.desc = None
        obj.type = CommandType.undefined
        obj.conf = ConformanceRequirement.O
        return obj

    @staticmethod
    def get(key: 'str', default: 'Optional[str]' = None) -> '{NAME}':
        """Backport support for original codes.

        Args:
            key: Key to get enum item. Looked up case-insensitively, since
                member names are canonicalised to upper case on registration.
            default: Default value if not found.

        :meta private:
        """
        name = key.upper()
        if name not in {NAME}._member_map_:  # type: ignore[misc]  # pylint: disable=no-member
            # NOTE: the value is ``default`` if the caller supplied one, or
            # else ``key`` exactly as given -- never ``name`` -- so an
            # unregistered member's value is the caller's own casing, the
            # same convention :meth:`_unregistered_member` documents and
            # :class:`~pcapkit.const.ftp.command.FEATCode` already followed
            # unchanged. Two calls naming the same command in different
            # case, e.g. ``get('xyzw')`` and ``get('XYZW')``, therefore build
            # results that are *not* equal -- each is exactly what its own
            # caller passed, which minting's ``_member_map_`` cache used to
            # paper over by returning the *first* casing seen for every
            # later call regardless of case. Losing that is the one
            # observable behaviour change in GitHub issue #860's conversion.
            return {NAME}._unregistered_member(default if default is not None else key, name)
        return {NAME}[name]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'str') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item. Matched case-insensitively against
                the canonical upper-case member names.

        """
        if not isinstance(value, str):
            raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')
        name = value.upper()
        if name in cls._member_map_:
            return cls._member_map_[name]  # type: ignore[return-value]
        return cls._unregistered_member(value, name)
'''.strip()  # type: Callable[[str, str, str, str, str], str]


class Command(Vendor):
    """FTP Command"""

    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions-2.csv'

    def process(self, data: 'list[str]') -> 'tuple[list[str], list[str]]':
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            :class:`Command`'s enumeration fields, and every distinct
            per-command keyword the ``FEAT code`` column names --
            :class:`FEATCode` must declare these as real members (GitHub
            issue #860), rather than the old approach of minting one as an
            incidental side effect the first time a :class:`Command` row
            referencing it was evaluated at import time.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = collections.OrderedDict()  # type: OrderedDict[str, str]
        feat_codes = collections.OrderedDict()  # type: OrderedDict[str, str]
        for item in reader:
            cmmd = item[0].strip('+')
            feat = item[1] or None
            desc = re.sub(r'{.*}', r'', item[2]).strip() or None
            kind = ' | '.join(KIND[s] for s in item[3].split('/') if s in KIND) or None
            conf = CONF.get(item[4].split()[0])

            temp = []  # type: list[str]
            #for rfc in filter(lambda s: 'RFC' in s, re.split(r'\[|\]', item[5])):
            #    temp.append(f'[{rfc[:3]} {rfc[3:]}]')
            for rfc in filter(None, map(lambda s: s.strip(), re.split(r'\[|\]', item[5]))):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    temp.append(f'[:rfc:`{rfc[3:]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            cmmt = self.wrap_comment(f'{desc} {"".join(temp)}')

            if cmmd == '-N/A-':
                cmmd = cast('str', feat)

            if isinstance(feat, str):
                # NOTE: GitHub issue #860. Every FEAT code the registry
                # names -- lower-case group marker or upper-case per-command
                # keyword alike -- is now a declared member of FEATCode (see
                # feat_codes below and FEATCode's own template), so both
                # cases resolve by plain attribute access; neither ever
                # calls FEATCode(...) at import time any more, which used to
                # mint the upper-case ones as a side effect of evaluating
                # this very module.
                if feat.isupper() and feat not in feat_codes:
                    feat_codes[feat] = f'#: {cmmt}\n    {feat} = {feat!r}'
                feat = f'FEATCode.{feat}'

            pres = f"{cmmd}: 'Command' = {cmmd!r}, {feat}, {desc!r}, {kind or 0}, {conf}"
            sufs = f'#: {cmmt}'

            enum[cmmd] = f'{sufs}\n    {pres}'
        return list(enum.values()), list(feat_codes.values())

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        enum, feat_codes = self.process(data)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum)).strip()
        FEAT = '\n\n    '.join(map(lambda s: s.rstrip(), feat_codes)).strip()

        return LINE(self.NAME, self.DOCS, ENUM, FEAT, self.__module__)


if __name__ == '__main__':
    sys.exit(Command())  # type: ignore[arg-type]
