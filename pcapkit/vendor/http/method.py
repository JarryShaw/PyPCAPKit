# -*- coding: utf-8 -*-
"""HTTP Method
=================

.. module:: pcapkit.vendor.http.method

This module contains the vendor crawler for **HTTP Method**,
which is automatically generating :class:`pcapkit.const.http.method.Method`.

"""
import csv
import re
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from typing import Callable

__all__ = ['Method']

#: Default constant template of enumeration registry from IANA CSV.
LINE = lambda NAME, DOCS, ENUM, MODL: f'''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""{(name := DOCS.split(' [', maxsplit=1)[0])}
{'=' * (len(name) + 6)}

.. module:: {MODL.replace('vendor', 'const')}

This module contains the constant enumeration for **{name}**,
which is automatically generated from :class:`{MODL}.{NAME}`.

"""

from typing import TYPE_CHECKING

from aenum import StrEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any, Optional, Type

__all__ = ['{NAME}']

class {NAME}(EnumRegistry, StrEnum):
    """[{NAME}] {DOCS}

    .. versionchanged:: 1.5.0

       Neither ``_missing_`` nor ``get()`` mints a member, per the owner's
       ruling on GitHub issue :issue:`860`: only IANA-registered values are
       legitimate members, and a new one is created through :meth:`register`,
       which can supply :attr:`safe` and :attr:`idempotent` where a bare wire
       method verb carries neither. ``get()`` matches ``key`` case-sensitively,
       as :rfc:`9110` makes the method token (:issue:`896`), and checks it
       against member values as well as names (:issue:`908`). A member's
       :class:`str` payload is its value, so ``Method.GET == 'GET'``
       (:issue:`870`).

    """

    if TYPE_CHECKING:
        #: Safe method.
        safe: 'bool'
        #: Idempotent method.
        idempotent: 'bool'

    def __new__(cls, value: 'str', safe: 'bool' = False,
                idempotent: 'bool' = False) -> 'Type[{NAME}]':
        obj = str.__new__(cls, value)
        obj._value_ = value

        obj.safe = safe
        obj.idempotent = idempotent

        return obj

    def __repr__(self) -> 'str':
        return f'<{{self.__class__.__name__}}.{{self._value_}}>'

    {ENUM}

    @classmethod
    def _unregistered_member(cls, value: 'str', name: 'str') -> '{NAME}':
        """Build a member absent from this registry's own lookup tables.

        Leaves :attr:`safe` and :attr:`idempotent` at the same defaults
        :meth:`__new__` itself would, rather than missing entirely --
        :meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member`
        bypasses :meth:`__new__` (it calls :class:`str`'s directly), so
        those attributes would otherwise be absent. There is no more
        specific value to reconstruct them from -- a bare wire method verb
        carries neither, which is exactly the owner's reasoning for why
        ``get()``/``_missing_`` must not mint one: :meth:`register` is the
        path that can actually supply them.

        Args:
            value: Value to get enum item -- the convention here, shared with
                :class:`~pcapkit.const.ftp.command.FEATCode` and
                :class:`~pcapkit.const.ftp.command.Command`, is the caller's
                own casing, unchanged: an unregistered member's *value* is
                exactly what was observed on the wire, matching how a
                *registered* member's own value is exactly what was
                declared, never reformatted. Only :attr:`name` -- the
                identifier, not the value -- is canonicalised.

                A *registered* member carries its value the same way:
                :meth:`__new__` passes ``value`` to ``str.__new__``, as
                :class:`~pcapkit.const.ftp.command.Command`'s own
                ``__new__`` does (:issue:`870`), so both kinds of member
                carry their own value as real :class:`str` content
                (``str(Method.GET) == 'GET'`` and
                ``str(Method('frob')) == 'frob'``).
            name: Bare label for the unregistered member -- here, the
                canonical upper-case form of ``value``, matching the name
                every *registered* member of this class is looked up by,
                since :issue:`860`'s open-vocabulary registries have no manufactured
                placeholder label to fall back to.

        """
        obj = super()._unregistered_member(value, name)
        obj.safe = False
        obj.idempotent = False
        return obj

    @classmethod
    def get(cls, key: 'str', default: 'Optional[str]' = None) -> '{NAME}':
        """Backport support for original codes.

        Delegates to :meth:`~pcapkit.corekit.enum.EnumLookup.get` for the
        lookup itself, so ``key`` is checked against member values as well
        as names (GitHub issue :issue:`908`). That is what resolves the two
        IANA methods whose member *name* differs from their *value* --
        ``BASELINE_CONTROL`` / ``'BASELINE-CONTROL'`` and
        ``VERSION_CONTROL`` / ``'VERSION-CONTROL'``, a hyphen being unusable
        in a Python identifier -- which :meth:`_missing_` (and so the
        constructor) also finds by value.

        It is a :class:`classmethod`, as the base is, because a
        zero-argument ``super()`` needs a first argument to bind
        (:issue:`908`). ``{NAME}.get('X')`` binds the same as it would on a
        :class:`staticmethod`.

        ``default`` does not follow the base's ``NO_DEFAULT`` sentinel and
        value-only fallback: the base's ``default`` must name a
        *registered* value (resolved through ``_value2member_map_``), while
        this override's ``default`` supplies the *value* of the
        unregistered member it builds on a miss.

        .. versionchanged:: 1.5.0

           A non-:class:`str` ``key`` raises :exc:`ValueError`
           (:issue:`908`). ``get(42)`` and ``get(None)`` raised
           :exc:`AttributeError` from ``key.upper()``, and ``get(b'GET')``
           raised :exc:`TypeError`.

        Args:
            key: Key to get enum item. Looked up case-**sensitively**,
                per :rfc:`9110#section-9.1` -- the method token is
                case-sensitive, unlike
                :meth:`~pcapkit.const.ftp.command.Command.get`'s equivalent override, which stays
                case-insensitive because :rfc:`959#section-5` says FTP
                command codes are not. Checked against both member names
                and values, via the base's own precedence -- name before
                value -- so a value-only match such as
                ``'BASELINE-CONTROL'`` resolves too (:issue:`908`).
            default: Value for the unregistered member built when ``key``
                matches neither a name nor a value. ``None``, the
                default, uses ``key`` itself.

        Raises:
            ValueError: If ``key`` is not a :class:`str`. This reaches the
                caller from the base's non-``str`` branch, where
                :meth:`_validate_value` refuses it before ``cls(key)`` could
                reach ``_missing_``, and is **not** caught by
                the ``except KeyError`` fallback below -- only a failed
                *name* lookup is. Raising is the intended behaviour for
                ``get(b'GET')`` as well: a member whose name and
                value were both the :class:`bytes` object is not a thing
                this registry should hand back.

        :meta private:
        """
        try:
            return super().get(key)
        except KeyError:
            # NOTE: the value is ``default`` if the caller supplied one, or
            # else ``key`` exactly as given -- never its upper-cased form --
            # so an unregistered member's value is the caller's own casing,
            # the same convention :meth:`_unregistered_member` documents and
            # :class:`~pcapkit.const.ftp.command.FEATCode` already followed.
            # The name is always the canonical upper-case form, matching
            # :meth:`_missing_` and every registered member's own name. Two
            # calls naming the same method in different case, e.g.
            # ``get('frob')`` and ``get('FROB')``, therefore build results
            # that are *not* equal -- each is exactly what its own caller
            # passed, per GitHub issue #860's conversion away from minting.
            return cls._unregistered_member(default if default is not None else key, key.upper())

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it is a :class:`str`, as :meth:`_missing_` does.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with the check :meth:`_missing_` makes, and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`get` refuses, in the same words (:issue:`1816`). Any
        :class:`str` passes, since :meth:`get` and :meth:`_missing_` resolve
        every one.

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
                the canonical upper-case member names -- deliberately unlike
                :meth:`get`, which is case-**sensitive** per
                :rfc:`9110#section-9.1`. The split was ruled deliberate on
                GitHub issue :issue:`896`; GitHub issue :issue:`908` is the pointer between
                the two, so the two rationales are not left contradicting each
                other with nothing tying them together.

        """
        if not isinstance(value, str):
            raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')
        name = value.upper()
        if name in cls._member_map_:
            return cls._member_map_[name]  # type: ignore[return-value]
        return cls._unregistered_member(value, name)
'''.strip()  # type: Callable[[str, str, str, str], str]


class Method(Vendor):
    """HTTP Method"""

    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/http-methods/methods.csv'

    def process(self, data: 'list[str]') -> 'list[str]':  # type: ignore[override]
        """Process CSV data.

        Args:
            data: CSV data.

        Returns:
            Enumeration fields.

        """
        reader = csv.reader(data)
        next(reader)  # header

        enum = []  # type: list[str]
        for item in reader:
            meth = item[0]
            if meth == '*':
                continue

            safe = item[1]
            idem = item[2]
            rfcs = item[3]

            temp = []  # type: list[str]
            for rfc in self.split_references(rfcs):
                if 'RFC' in rfc and re.match(r'\d+', rfc[3:]):
                    #temp.append(f'[{rfc[:3]} {rfc[3:]}]')
                    temp_split = rfc[3:].split(', ', maxsplit=1)
                    if len(temp_split) > 1:
                        temp.append(f'[:rfc:`{temp_split[0]}#{temp_split[1].lower()}`]'.replace(' ', '-'))
                    else:
                        temp.append(f'[:rfc:`{temp_split[0]}`]')
                else:
                    temp.append(f'[{rfc}]'.replace('_', ' '))
            desc = self.wrap_comment(re.sub(
                r'\r*\n', ' ', f'{meth} {"".join(temp) if rfcs else ""}',
                flags=re.MULTILINE))

            name = self.safe_name(meth).upper()
            safe_flag = 'True' if safe == 'yes' else 'False'
            idem_flag = 'True' if idem == 'yes' else 'False'

            pres = f"{name} = {meth!r}, {safe_flag}, {idem_flag}"
            sufs = f'#: {desc}'

            enum.append(f'{sufs}\n    {pres}')
        return enum

    def context(self, data: 'list[str]') -> 'str':
        """Generate constant context.

        Args:
            data: CSV data.

        Returns:
            Constant context.

        """
        enum = self.process(data)
        ENUM = '\n\n    '.join(map(lambda s: s.rstrip(), enum)).strip()

        return LINE(self.NAME, self.DOCS, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(Method())  # type: ignore[arg-type]
