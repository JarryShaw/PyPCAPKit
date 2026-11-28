# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""SMTP Command
==================

.. module:: pcapkit.const.smtp.command

This module contains the constant enumeration for **SMTP Command**,
which is automatically generated from :class:`pcapkit.vendor.smtp.command.Command`.

"""

from typing import TYPE_CHECKING

from aenum import StrEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.corekit.sentinels import NO_DEFAULT
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Command']


class Command(EnumRegistry, StrEnum):
    """[Command] SMTP Command"""

    #: Extended HELLO [:rfc:`5321#section-4.1.1.1`]
    EHLO = 'EHLO'

    #: HELLO [:rfc:`5321#section-4.1.1.1`]
    HELO = 'HELO'

    #: MAIL [:rfc:`5321#section-4.1.1.2`]
    MAIL = 'MAIL'

    #: RECIPIENT [:rfc:`5321#section-4.1.1.3`]
    RCPT = 'RCPT'

    #: DATA [:rfc:`5321#section-4.1.1.4`]
    DATA = 'DATA'

    #: RESET [:rfc:`5321#section-4.1.1.5`]
    RSET = 'RSET'

    #: VERIFY [:rfc:`5321#section-4.1.1.6`]
    VRFY = 'VRFY'

    #: EXPAND [:rfc:`5321#section-4.1.1.7`]
    EXPN = 'EXPN'

    #: HELP [:rfc:`5321#section-4.1.1.8`]
    HELP = 'HELP'

    #: NOOP [:rfc:`5321#section-4.1.1.9`]
    NOOP = 'NOOP'

    #: QUIT [:rfc:`5321#section-4.1.1.10`]
    QUIT = 'QUIT'

    @classmethod
    def get(cls, key: 'Any', default: 'Any' = NO_DEFAULT) -> 'Command':
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
            raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')

    @classmethod
    def _missing_(cls, value: 'str') -> 'Command':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item, matched case-insensitively against the
                member names (:rfc:`5321#section-2.4`). A verb no member names
                resolves to an unregistered member named after it in upper case
                and valued as given (:issue:`860`).

        """
        if not isinstance(value, str):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        name = value.upper()
        if name in cls._member_map_:  # pylint: disable=no-member
            return cls._member_map_[name]  # pylint: disable=no-member
        return cls._unregistered_member(value, name)
