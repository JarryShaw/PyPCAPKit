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

from pcapkit.corekit.enum import NO_DEFAULT, EnumLookup, EnumRegistry

if TYPE_CHECKING:
    from typing import Any, Optional, Type

__all__ = ['{NAME}']


class FEATCode(EnumRegistry, StrEnum):
    """Keyword returned in FEAT response line for this command/extension,
    c.f., :rfc:`5797#section-3`.

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
    def get(cls, key: 'Any', default: 'Any' = NO_DEFAULT) -> 'FEATCode':
        """Resolve ``key`` case-insensitively, per :rfc:`5797#section-2`.

        One of the few case-insensitive overrides the ruling on GitHub issue
        #877 allows, and the registry's own defining document states the
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
        recommendation, while 5 of this registry's 15 codes are registered in
        lower case -- measured on the IANA CSV: 10 distinct all-upper-case
        keywords against ``base``, ``feat``, ``hist``, ``nat6`` and ``secu``,
        with none mixed. Without this override ``get('BASE')`` raised
        :exc:`KeyError`, which is the defect GitHub issue #903's audit found.

        The obvious objection, answered: :rfc:`5797` uses case *presentationally*
        to tell a real keyword from a placeholder -- *"defined FEAT keywords
        codes are listed in all uppercase, whereas placeholder keywords ... are
        listed in lowercase"* -- so folding might look like it discards that
        distinction. It does not. Only the inbound ``key`` is folded; every
        member keeps the registrar's own casing, per the same ruling's *"enum
        should honour and keep their original writings as in the registrars"*,
        so ``get('BASE').name`` is still ``'base'`` and still says placeholder.
        And the uniqueness rule quoted above is what makes that safe: a real
        keyword ``BASE`` could not be registered alongside the placeholder
        ``base``, so there is no second member for the fold to hide.

        Folds only as a *fallback*. An exact name or value hit is delegated to
        :meth:`~pcapkit.corekit.enum.EnumLookup.get` untouched, so the base's
        own precedence -- name before value -- and its non-minting ``str``
        path both survive: nothing here calls ``cls(key)``, so a key matching
        no member, folded or not, still raises rather than growing the
        registry. ``get('ZZ-NOT-REAL')`` therefore still raises
        :exc:`KeyError` while ``FEATCode('ZZ-NOT-REAL')`` still yields an
        unregistered member, exactly as before.

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

    Re-parented onto :class:`~pcapkit.corekit.enum.EnumLookup` per GitHub
    issue #930, finishing #877's phase 2. Pure re-parenting as far as
    ``get``/``get_all`` are concerned -- this class defines no ``get`` of its
    own to reconcile with the base -- and its own :meth:`_missing_` range
    guard below is untouched, since :class:`EnumLookup` does not touch that
    hook.

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

    Re-parented onto :class:`~pcapkit.corekit.enum.EnumLookup` per GitHub
    issue #930, finishing #877's phase 2 -- pure re-parenting, since this
    class defines neither ``get`` nor ``_missing_`` of its own to reconcile
    with the base.

    """

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
