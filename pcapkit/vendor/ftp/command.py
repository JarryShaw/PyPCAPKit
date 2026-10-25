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

#: Default constant template of enumeration registry from IANA CSV.
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

from pcapkit.corekit.enum import EnumLookup, EnumRegistry
from pcapkit.corekit.sentinels import NO_DEFAULT
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any, Optional, Type

__all__ = ['{NAME}']


class FEATCode(EnumRegistry, StrEnum):
    """Keyword returned in FEAT response line for this command/extension,
    c.f., :rfc:`5797#section-3`.

    .. note::

       Declares every FEAT keyword the IANA registry's own ``FEAT code``
       column names -- the group markers below plus the per-command
       keywords generated after them (data-driven, not hand-picked; see
       :meth:`~pcapkit.vendor.ftp.command.Command.process`) -- rather than
       minting the per-command ones at import time as an incidental side
       effect of building :class:`Command`'s own rows. GitHub issue :issue:`860`:
       that import-time mutation was the same defect shape :issue:`775` removed
       from :class:`~pcapkit.const.pcapng.filter_type.FilterType`. ``_missing_``
       still unmints for a keyword that
       turns up on the wire but names none of these -- the extendability the
       owner conditionally asked to keep on GitHub issue :issue:`860`: unsure what a
       FEAT value absent from the RFC's list means in the CSV table, the owner
       said that if the expected handling is this registry's approach, as industry
       convention has it, the registry stays extendable as is, and then approved
       declaring the registry's keywords as real members with ``_missing_``
       still covering the rest. No custom ``__new__`` here, so the base's
       generic :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
       needs no override.

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
    def get(cls, key: 'Any', default: 'Any' = NO_DEFAULT) -> 'FEATCode':
        """Resolve ``key`` case-insensitively, per :rfc:`5797#section-2`.

        One of the few case-insensitive overrides the ruling on GitHub issue
        :issue:`877` allows, and the registry's own defining document states the
        comparison rule outright rather than leaving it to be inferred --
        :rfc:`5797#section-2`, on the ``FEAT Code`` column this class is
        generated from: *"IANA maintains uniqueness of feature names (FEAT
        codes) based on case-insensitive comparison."* Two FEAT codes
        therefore cannot differ only by case, so folding the caller's key
        cannot resolve ambiguously.

        :rfc:`2389#section-3.2`, which defines the ``FEAT`` response the
        codes appear in, points the same way from the wire side: *"The
        feature-label and feature-parms are nominally case sensitive,
        however ... it is to be expected that those definitions will usually
        specify the label and parameters in a case independent manner. Where
        this is done, implementations are recommended to use upper case
        letters when transmitting the feature response."* A caller feeding a
        ``FEAT`` response line is therefore holding upper case by
        recommendation, while some of this registry's codes are registered in
        lower case -- measured on the IANA CSV: ``base``, ``feat``, ``hist``,
        ``nat6`` and ``secu``, against all-upper-case keywords for the rest,
        with none mixed. Without this override ``get('BASE')`` raises
        :exc:`KeyError`, which is the defect GitHub issue :issue:`903`'s audit found.

        The obvious objection, answered: :rfc:`5797` uses case *presentationally*
        to tell a real keyword from a placeholder -- *"defined FEAT keywords
        codes are listed in all uppercase, whereas placeholder keywords ... are
        listed in lowercase"* -- so folding might look like it discards that
        distinction. It does not. Only the inbound ``key`` is folded; every
        member keeps the registrar's own casing, and the fold itself is backed by
        the RFC: the final ruling on GitHub issue :issue:`877` is that an enum treats its
        values as case-insensitive where the RFC states they are, and as
        case-sensitive otherwise. So ``get('BASE').name`` is still ``'base'`` and
        still says placeholder. And the uniqueness rule quoted above is what makes
        that safe: a real keyword ``BASE`` could not be registered alongside the
        placeholder ``base``, so there is no second member for the fold to hide.

        Folds only as a *fallback*. An exact name or value hit is delegated to
        :meth:`~pcapkit.corekit.enum.EnumLookup.get` untouched, so the base's
        own precedence -- name before value -- and its non-minting ``str``
        path both survive: nothing here calls ``cls(key)``, so a key matching
        no member, folded or not, still raises rather than growing the
        registry. ``get('ZZ-NOT-REAL')`` therefore raises
        :exc:`KeyError` while ``FEATCode('ZZ-NOT-REAL')`` yields an
        unregistered member.

        Args:
            key: Name or value to look up. A non-``str`` key is passed
                straight through, since case cannot apply to it.
            default: As :meth:`~pcapkit.corekit.enum.EnumLookup.get`. Not
                folded -- it names an already-registered value rather than
                arriving from the wire, so the caller spells it from this
                module.

        Returns:
            The canonical member for ``key``, or for ``default``.

        Raises:
            KeyError: If no member matches ``key`` exactly or case-insensitively
                and there is no usable ``default``.
            ValueError: As :meth:`~pcapkit.corekit.enum.EnumLookup.get`, for a
                non-``str`` key.

        """
        if isinstance(key, str) and not (
            key in cls._member_map_ or  # pylint: disable=no-member
            key in cls._value2member_map_
        ):
            folded = key.casefold()
            for name, member in cls._member_map_.items():  # pylint: disable=no-member
                if name.casefold() == folded:
                    return member
            for member in cls._value2member_map_.values():
                if member.value.casefold() == folded:
                    return member
        return super().get(key, default)

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it is a :class:`str`, as :meth:`_missing_` does.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with the check :meth:`_missing_` makes, and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`get` refuses, in the same words (:issue:`1816`). Any
        :class:`str` passes, since :meth:`_missing_` resolves every one.

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` is not a :class:`str`. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not isinstance(value, str):
            raise EnumValueError(f'{{value!r}} is not a valid {{cls.__name__}}')

    @classmethod
    def _missing_(cls, value: 'str') -> 'FEATCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not isinstance(value, str):
            raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')
        return cls._unregistered_member(value, value.upper())


class CommandType(EnumLookup, IntFlag):
    """Type of "kind" of command, based on :rfc:`959#section-4`.

    Built on :class:`~pcapkit.corekit.enum.EnumLookup` per GitHub issue
    :issue:`930`, which finished :issue:`877`'s phase 2. This class defines no
    ``get`` of its own, so ``get``/``get_all`` are the base's, and its own
    :meth:`_missing_` range guard below stands as written, since
    :class:`~pcapkit.corekit.enum.EnumLookup` does not touch that hook.

    """

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


class ConformanceRequirement(EnumLookup, IntEnum):
    """Expectation for support in modern FTP implementations.

    Built on :class:`~pcapkit.corekit.enum.EnumLookup` per GitHub issue
    :issue:`930`, which finished :issue:`877`'s phase 2. This class defines
    neither ``get`` nor ``_missing_`` of its own.

    """

    #: Mandatory to implement.
    M = auto()
    #: Optional.
    O = auto()
    #: Historic.
    H = auto()


class {NAME}(EnumRegistry, StrEnum):
    """[{NAME}] {DOCS}"""

    if TYPE_CHECKING:
        #: Feature code. Keyword returned in FEAT response line for this command/extension,
        #: c.f., :rfc:`5797#section-2.2`.
        feat: 'Optional[FEATCode]'
        #: Brief description of command / extension.
        desc: 'Optional[str]'
        #: Type of "kind" of command, based on :rfc:`959#section-4`.
        type: 'CommandType'
        #: Expectation for support in modern FTP implementations.
        conf: 'ConformanceRequirement'

    def __new__(cls, name: 'str', feat: 'Optional[FEATCode]' = None,
                desc: 'Optional[str]' = None, type: 'CommandType' = CommandType.undefined,
                conf: 'ConformanceRequirement' = ConformanceRequirement.O) -> 'Type[{NAME}]':
        """Create a member from a registry row.

        Args:
            name: Command word, which is also the member's value.
            feat: Feature code of the ``FEAT`` response line for the command.
            desc: Brief description of the command.
            type: Kind of command, based on :rfc:`959#section-4`.
            conf: Expectation for support in modern FTP implementations.

        """
        obj = str.__new__(cls, name)
        obj._value_ = name

        obj.feat = feat
        obj.desc = desc
        obj.type = type
        obj.conf = conf

        return obj

    def __repr__(self) -> 'str':
        """Show the member with its description, as ``<Command.NAME: description>``."""
        return f'<{{self.__class__.__name__}}.{{self._name_}}: {{self.desc}}>'

    {ENUM}

    @classmethod
    def _unregistered_member(cls, value: 'str', name: 'str') -> '{NAME}':
        """Build a member absent from this registry's own lookup tables.

        Leaves :attr:`feat`, :attr:`desc`, :attr:`type` and :attr:`conf` at
        the same defaults :meth:`__new__` itself would, rather than missing
        entirely --
        :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
        bypasses :meth:`__new__` (it calls
        :class:`str`'s directly), so those attributes would otherwise
        be absent and :meth:`__repr__` (which reads :attr:`desc`) would
        raise on the result. There is no more specific value to reconstruct
        them from -- a bare wire command word carries none of them,
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
                since :issue:`860`'s open-vocabulary registries have no manufactured
                placeholder label to fall back to.

        """
        obj = super()._unregistered_member(value, name)
        obj.feat = None
        obj.desc = None
        obj.type = CommandType.undefined
        obj.conf = ConformanceRequirement.O
        return obj

    @classmethod
    def register(cls, value: 'str', name: 'str') -> '{NAME}':
        """Register a new command ``value`` under ``name``, upper-cased.

        :meth:`get` and :meth:`_missing_` look a command up by its
        upper-case name, so ``name`` is canonicalised to upper case here
        before :meth:`~pcapkit.corekit.enum.EnumRegistry.register` mints it.
        ``value`` is kept as given, as a declared member's value is.

        Args:
            value: Value of the new member.
            name: Name of the new member, in any case.

        Returns:
            The newly registered member.

        Raises:
            ValueError: As :meth:`~pcapkit.corekit.enum.EnumRegistry.register`.

        """
        return super().register(value, name.upper())

    @classmethod
    def register_alias(cls, value: 'str', name: 'str') -> '{NAME}':
        """Add ``name``, upper-cased, as a further name for the member at ``value``.

        Canonicalised for the same reason as :meth:`register`, so that
        :meth:`get` finds the alias.

        Args:
            value: Value of the existing member to alias.
            name: Alias to add for it, in any case.

        Returns:
            The existing member, now reachable under the upper-cased ``name``
            as well.

        Raises:
            ValueError: As
                :meth:`~pcapkit.corekit.enum.EnumRegistry.register_alias`.

        """
        return super().register_alias(value, name.upper())

    @classmethod
    def get(cls, key: 'str', default: 'Optional[str]' = None) -> '{NAME}':
        """Resolve ``key`` to a member, matching the command code case-insensitively.

        A non-:class:`str` ``key`` is delegated to
        :meth:`~pcapkit.corekit.enum.EnumLookup.get`, as
        :meth:`Method.get <pcapkit.const.http.method.Method.get>` delegates
        every key, so :meth:`_validate_value` refuses it there rather than
        ``key.upper()`` being called on it (GitHub issue :issue:`1824`). It is
        a :class:`classmethod`, as the base is, because a zero-argument
        ``super()`` needs a first argument to bind. ``{NAME}.get('X')`` binds
        the same as it would on a :class:`staticmethod`.

        ``default`` is not forwarded on that path, as :meth:`Method.get <pcapkit.const.http.method.Method.get>` does not
        forward its own: here it supplies the *value* of the unregistered
        member built on a name miss, while the base's ``default`` must name a
        *registered* value. A refused ``key`` therefore raises whatever
        ``default`` is.

        Args:
            key: Key to get enum item. Looked up case-insensitively, as
                :rfc:`959#section-5` treats FTP command codes, against member
                names canonicalised to upper case on registration.
            default: Value for the unregistered member built when ``key``
                matches no member name. ``None``, the default, uses ``key``
                itself.

        Returns:
            The member named ``key`` upper-cased. On a miss, an unregistered
            member with that name and the value ``default`` (or ``key``),
            which is not added to the lookup tables, so ``get`` never registers
            a command (:issue:`860`).

        Raises:
            EnumValueError: If ``key`` is not a :class:`str`. This reaches the
                caller from the base's non-``str`` branch, where
                :meth:`_validate_value` refuses it before ``cls(key)`` could
                reach :meth:`_missing_`. A :exc:`ValueError`, so an
                ``except ValueError`` caller is unaffected.

        """
        if not isinstance(key, str):
            # NOTE: unreachable only by the ``str`` annotation, which a caller
            # at run time need not honour (GitHub issue #1824).
            return super().get(key)  # type: ignore[unreachable]
        name = key.upper()
        if name not in cls._member_map_:  # pylint: disable=no-member
            # NOTE: the value is ``default`` if the caller supplied one, or
            # else ``key`` exactly as given -- never ``name`` -- so an
            # unregistered member's value is the caller's own casing, the
            # same convention :meth:`_unregistered_member` documents and
            # :class:`~pcapkit.const.ftp.command.FEATCode` follows
            # unchanged. Two calls naming the same command in different
            # case, e.g. ``get('xyzw')`` and ``get('XYZW')``, therefore build
            # results that are *not* equal -- each is exactly what its own
            # caller passed. Minting instead would return, through the
            # ``_member_map_`` cache, the *first* casing seen for every later
            # call regardless of case (GitHub issue #860).
            return cls._unregistered_member(default if default is not None else key, name)
        return cls._member_map_[name]  # pylint: disable=no-member

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it is a :class:`str`, as :meth:`_missing_` does.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with the check :meth:`_missing_` makes, and the message it raises, so
        :meth:`register` refuses a value the constructor refuses, in the same
        words (:issue:`1816`). :meth:`get` reaches it as well, through the
        base, for every non-:class:`str` key (:issue:`1824`), so it refuses
        the same values. Any :class:`str` passes, since :meth:`_missing_`
        resolves every one.

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` is not a :class:`str`. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not isinstance(value, str):
            raise EnumValueError(f'{{value!r}} is not a valid {{cls.__name__}}')

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
            return cls._member_map_[name]
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
            :class:`~pcapkit.const.ftp.command.FEATCode` must declare these as real members (GitHub
            issue :issue:`860`), rather than minting one as an incidental side
            effect the first time a :class:`Command` row referencing it is
            evaluated at import time.

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
            for rfc in map(str.strip, self.split_references(item[5])):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    # NOTE: IANA has put a section inside the citation since
                    # 2026-10-13 -- ``ALGS`` cites ``[RFC 6384, Section 11]``,
                    # formerly ``[RFC6384] Section 11`` -- and the whole of
                    # ``rfc[3:]`` would make that a role no RFC answers (#1664).
                    num, _, sec = rfc[3:].partition(', Section ')
                    temp.append(f'[:rfc:`{num}#section-{sec}`]' if sec else f'[:rfc:`{num}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            cmmt = self.wrap_comment(f'{desc} {"".join(temp)}')

            if cmmd == '-N/A-':
                cmmd = cast('str', feat)

            if isinstance(feat, str):
                # NOTE: GitHub issue #860. Every FEAT code the registry
                # names -- lower-case group marker or upper-case per-command
                # keyword alike -- is a declared member of FEATCode (see
                # feat_codes below and FEATCode's own template), so both
                # cases resolve by plain attribute access, and nothing calls
                # FEATCode(...) at import time, which would mint the
                # upper-case ones as a side effect of evaluating this very
                # module.
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
