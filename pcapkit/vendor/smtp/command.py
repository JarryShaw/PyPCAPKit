# -*- coding: utf-8 -*-
"""SMTP Command
==================

.. module:: pcapkit.vendor.smtp.command

This module contains the vendor crawler for **SMTP Command**,
which is automatically generating :class:`pcapkit.const.smtp.command.Command`.

No registry lists the SMTP commands: they are the sections of
:rfc:`5321#section-4.1.1`, so the crawler reads a ``DATA`` literal transcribed
from them, as :mod:`pcapkit.vendor.linux.arphrd` does (:ref:`const-vendor-pairing`).
A verb an extension adds, such as ``STARTTLS``, resolves to an unregistered member.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter
    from typing import Callable

__all__ = ['Command']

#: The commands of :rfc:`5321#section-4.1.1`, each verb mapped to the title of
#: its section and that section.
DATA = {
    'EHLO': ('Extended HELLO', ':rfc:`5321#section-4.1.1.1`'),
    'HELO': ('HELLO', ':rfc:`5321#section-4.1.1.1`'),
    'MAIL': ('MAIL', ':rfc:`5321#section-4.1.1.2`'),
    'RCPT': ('RECIPIENT', ':rfc:`5321#section-4.1.1.3`'),
    'DATA': ('DATA', ':rfc:`5321#section-4.1.1.4`'),
    'RSET': ('RESET', ':rfc:`5321#section-4.1.1.5`'),
    'VRFY': ('VERIFY', ':rfc:`5321#section-4.1.1.6`'),
    'EXPN': ('EXPAND', ':rfc:`5321#section-4.1.1.7`'),
    'HELP': ('HELP', ':rfc:`5321#section-4.1.1.8`'),
    'NOOP': ('NOOP', ':rfc:`5321#section-4.1.1.9`'),
    'QUIT': ('QUIT', ':rfc:`5321#section-4.1.1.10`'),
}  # type: dict[str, tuple[str, str]]

#: Constant template of the registry, a ``StrEnum``.
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
from pcapkit.corekit.sentinels import NO_DEFAULT
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['{NAME}']


class {NAME}(EnumRegistry, StrEnum):
    """[{NAME}] {DOCS}"""

    {ENUM}

    @classmethod
    def get(cls, key: 'Any', default: 'Any' = NO_DEFAULT) -> '{NAME}':
        """Resolve ``key`` to a member, folding a :class:`str` to upper case.

        Command verbs are not case-sensitive (:rfc:`5321#section-2.4`), and each
        member is named, and valued, its verb in upper case.

        Args:
            key: Key to get enum item.
            default: An already-registered value to fall back to, as
                :meth:`~pcapkit.corekit.enum.EnumLookup.get` takes it.

        Returns:
            The member ``key`` names or carries.

        Raises:
            EnumKeyError: If ``key`` names no member and there is no usable
                ``default``.
            EnumValueError: If ``key`` is not a :class:`str` and there is no
                usable ``default``.

        """
        if isinstance(key, str):
            return super().get(key.upper(), default)
        return super().get(key, default)

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it is a :class:`str`, as :meth:`_missing_` does.

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` is not a :class:`str`.

        """
        if not isinstance(value, str):
            raise EnumValueError(f'{{value!r}} is not a valid {{cls.__name__}}')

    @classmethod
    def _missing_(cls, value: 'str') -> '{NAME}':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item, matched case-insensitively against the
                member names (:rfc:`5321#section-2.4`). A verb no member names
                resolves to an unregistered member named after it in upper case
                and valued as given (:issue:`860`).

        """
        if not isinstance(value, str):
            raise ValueError(f'{{value!r}} is not a valid {{cls.__name__}}')
        name = value.upper()
        if name in cls._member_map_:  # pylint: disable=no-member
            return cls._member_map_[name]  # pylint: disable=no-member
        return cls._unregistered_member(value, name)
'''.strip()  # type: Callable[[str, str, str, str], str]


class Command(Vendor):
    """SMTP Command"""

    def request(self) -> 'dict[str, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.smtp.command.DATA`).

        """
        return DATA

    def count(self, data: 'dict[str, tuple[str, str]]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(data)

    def process(self, data: 'dict[str, tuple[str, str]]') -> 'list[str]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields.

        """
        enum = []  # type: list[str]
        for verb, (title, cite) in data.items():
            enum.append(f'#: {title} [{cite}]\n    {verb} = {verb!r}')
        return enum

    def context(self, data: 'dict[str, tuple[str, str]]') -> 'str':  # type: ignore[override]
        """Generate constant context.

        Args:
            data: Registry data.

        Returns:
            Constant context.

        """
        ENUM = '\n\n    '.join(self.process(data))
        return LINE(self.NAME, self.DOCS, ENUM, self.__module__)


if __name__ == '__main__':
    sys.exit(Command())  # type: ignore[arg-type]
