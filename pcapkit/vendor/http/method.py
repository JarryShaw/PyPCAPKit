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

#: Default constant template of enumerate registry from IANA CSV.
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

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['{NAME}']

class {NAME}(EnumRegistry, StrEnum):
    """[{NAME}] {DOCS}

    .. note::

       Neither ``_missing_`` nor ``get()`` mints any more, per the owner's
       ruling on GitHub issue #860: *"only IANA registered ones are legit
       values and we need register to properly create new entries. get will
       not have sufficient information to create new ones."* Concretely true
       here -- a bare wire method verb carries no
       :attr:`safe`/:attr:`idempotent`, so minting one used to register a
       permanent member with both hollowed out to their defaults;
       :meth:`register` is the path that can actually supply them.

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
        those two attributes would otherwise be absent. There is no more
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

                A *registered* member of this class used to carry something
                different here: GitHub issue #870 found that
                :meth:`__new__` called ``str.__new__(cls)`` with no
                argument at all, so every one of the 40 declared members'
                own :class:`str` payload was permanently empty regardless
                of ``value`` (``str(Method.GET) == ''``, and
                ``Method.GET == 'GET'`` was :obj:`False`) -- true on
                ``main`` at ``60b85e3a4`` as well as when this docstring
                was first written. #870 fixed :meth:`__new__` to
                ``str.__new__(cls, value)``, mirroring
                :class:`~pcapkit.const.ftp.command.Command`'s own
                ``__new__``, so a registered member's payload now agrees
                with an *unregistered* member built through this method:
                both carry their own value as real :class:`str` content
                (``str(Method('frob')) == 'frob'``).
            name: Bare label for the unregistered member -- here, the
                canonical upper-case form of ``value``, matching the name
                every *registered* member of this class is looked up by,
                since #860's open-vocabulary registries have no manufactured
                placeholder label to fall back to.

        """
        obj = super()._unregistered_member(value, name)
        obj.safe = False
        obj.idempotent = False
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
            # unchanged. Two calls naming the same method in different
            # case, e.g. ``get('frob')`` and ``get('FROB')``, therefore build
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
            for rfc in filter(None, re.split(r'\[|\]', rfcs)):
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
