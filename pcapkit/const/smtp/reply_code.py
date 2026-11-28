# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""SMTP Reply Code
=====================

.. module:: pcapkit.const.smtp.reply_code

This module contains the constant enumeration for **SMTP Reply Code**,
which is automatically generated from :class:`pcapkit.vendor.smtp.reply_code.ReplyCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ReplyCode']


class ReplyCode(EnumRegistry, IntEnum):
    """[ReplyCode] SMTP Reply Code"""

    #: System status, or system help reply [:rfc:`5321#section-4.2.3`]
    CODE_211 = 211

    #: Help message [:rfc:`5321#section-4.2.3`]
    CODE_214 = 214

    #: <domain> Service ready [:rfc:`5321#section-4.2.3`]
    CODE_220 = 220

    #: <domain> Service closing transmission channel [:rfc:`5321#section-4.2.3`]
    CODE_221 = 221

    #: Requested mail action okay, completed [:rfc:`5321#section-4.2.3`]
    CODE_250 = 250

    #: User not local; will forward to <forward-path> [:rfc:`5321#section-4.2.3`]
    CODE_251 = 251

    #: Cannot VRFY user, but will accept message and attempt delivery
    #: [:rfc:`5321#section-4.2.3`]
    CODE_252 = 252

    #: Start mail input; end with <CRLF>.<CRLF> [:rfc:`5321#section-4.2.3`]
    CODE_354 = 354

    #: <domain> Service not available, closing transmission channel
    #: [:rfc:`5321#section-4.2.3`]
    CODE_421 = 421

    #: Requested mail action not taken: mailbox unavailable
    #: [:rfc:`5321#section-4.2.3`]
    CODE_450 = 450

    #: Requested action aborted: local error in processing
    #: [:rfc:`5321#section-4.2.3`]
    CODE_451 = 451

    #: Requested action not taken: insufficient system storage
    #: [:rfc:`5321#section-4.2.3`]
    CODE_452 = 452

    #: Server unable to accommodate parameters [:rfc:`5321#section-4.2.3`]
    CODE_455 = 455

    #: Syntax error, command unrecognized [:rfc:`5321#section-4.2.3`]
    CODE_500 = 500

    #: Syntax error in parameters or arguments [:rfc:`5321#section-4.2.3`]
    CODE_501 = 501

    #: Command not implemented [:rfc:`5321#section-4.2.3`]
    CODE_502 = 502

    #: Bad sequence of commands [:rfc:`5321#section-4.2.3`]
    CODE_503 = 503

    #: Command parameter not implemented [:rfc:`5321#section-4.2.3`]
    CODE_504 = 504

    #: Authentication required [:rfc:`4954#section-6`][:rfc:`6409#section-4.3`]
    CODE_530 = 530

    #: Requested action not taken: mailbox unavailable [:rfc:`5321#section-4.2.3`]
    CODE_550 = 550

    #: User not local; please try <forward-path> [:rfc:`5321#section-4.2.3`]
    CODE_551 = 551

    #: Requested mail action aborted: exceeded storage allocation
    #: [:rfc:`5321#section-4.2.3`]
    CODE_552 = 552

    #: Requested action not taken: mailbox name not allowed
    #: [:rfc:`5321#section-4.2.3`]
    CODE_553 = 553

    #: Transaction failed [:rfc:`5321#section-4.2.3`]
    CODE_554 = 554

    #: MAIL FROM/RCPT TO parameters not recognized or not implemented
    #: [:rfc:`5321#section-4.2.3`]
    CODE_555 = 555

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 200 <= value <= 599 and value // 10 % 10 <= 5):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'ReplyCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 200 <= value <= 599 and value // 10 % 10 <= 5):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
