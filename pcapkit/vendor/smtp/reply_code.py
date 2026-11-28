# -*- coding: utf-8 -*-
"""SMTP Reply Code
=====================

.. module:: pcapkit.vendor.smtp.reply_code

This module contains the vendor crawler for **SMTP Reply Code**,
which is automatically generating :class:`pcapkit.const.smtp.reply_code.ReplyCode`.

No registry lists the SMTP reply codes: :rfc:`5321#section-4.2.3` does, so the
crawler reads a ``DATA`` literal transcribed from it, as
:mod:`pcapkit.vendor.linux.arphrd` does (:ref:`const-vendor-pairing`), with the
``530`` that :rfc:`4954#section-6` defines and :rfc:`6409#section-4.3` has a
submission server send. A code the ``Reply-code`` grammar admits with no member
is ``Unassigned``.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ReplyCode']

#: Each reply code mapped to its text, without the RFC's parenthetical notes,
#: and the sections that give it.
DATA = {
    211: ('System status, or system help reply', (':rfc:`5321#section-4.2.3`',)),
    214: ('Help message', (':rfc:`5321#section-4.2.3`',)),
    220: ('<domain> Service ready', (':rfc:`5321#section-4.2.3`',)),
    221: ('<domain> Service closing transmission channel', (':rfc:`5321#section-4.2.3`',)),
    250: ('Requested mail action okay, completed', (':rfc:`5321#section-4.2.3`',)),
    251: ('User not local; will forward to <forward-path>', (':rfc:`5321#section-4.2.3`',)),
    252: ('Cannot VRFY user, but will accept message and attempt delivery', (':rfc:`5321#section-4.2.3`',)),
    354: ('Start mail input; end with <CRLF>.<CRLF>', (':rfc:`5321#section-4.2.3`',)),
    421: ('<domain> Service not available, closing transmission channel', (':rfc:`5321#section-4.2.3`',)),
    450: ('Requested mail action not taken: mailbox unavailable', (':rfc:`5321#section-4.2.3`',)),
    451: ('Requested action aborted: local error in processing', (':rfc:`5321#section-4.2.3`',)),
    452: ('Requested action not taken: insufficient system storage', (':rfc:`5321#section-4.2.3`',)),
    455: ('Server unable to accommodate parameters', (':rfc:`5321#section-4.2.3`',)),
    500: ('Syntax error, command unrecognized', (':rfc:`5321#section-4.2.3`',)),
    501: ('Syntax error in parameters or arguments', (':rfc:`5321#section-4.2.3`',)),
    502: ('Command not implemented', (':rfc:`5321#section-4.2.3`',)),
    503: ('Bad sequence of commands', (':rfc:`5321#section-4.2.3`',)),
    504: ('Command parameter not implemented', (':rfc:`5321#section-4.2.3`',)),
    530: ('Authentication required', (':rfc:`4954#section-6`', ':rfc:`6409#section-4.3`')),
    550: ('Requested action not taken: mailbox unavailable', (':rfc:`5321#section-4.2.3`',)),
    551: ('User not local; please try <forward-path>', (':rfc:`5321#section-4.2.3`',)),
    552: ('Requested mail action aborted: exceeded storage allocation', (':rfc:`5321#section-4.2.3`',)),
    553: ('Requested action not taken: mailbox name not allowed', (':rfc:`5321#section-4.2.3`',)),
    554: ('Transaction failed', (':rfc:`5321#section-4.2.3`',)),
    555: ('MAIL FROM/RCPT TO parameters not recognized or not implemented', (':rfc:`5321#section-4.2.3`',)),
}  # type: dict[int, tuple[str, tuple[str, ...]]]


class ReplyCode(Vendor):
    """SMTP Reply Code"""

    #: Value limit checker. It is the ``Reply-code`` grammar of
    #: :rfc:`5321#section-4.2`, a first digit of 2 to 5 and a second of 0 to 5.
    FLAG = 'isinstance(value, int) and 200 <= value <= 599 and value // 10 % 10 <= 5'

    def request(self) -> 'dict[int, tuple[str, tuple[str, ...]]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.smtp.reply_code.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, tuple[str, tuple[str, ...]]]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(f'CODE_{code}' for code in data)

    def process(self, data: 'dict[int, tuple[str, tuple[str, ...]]]',  # type: ignore[override]
                ) -> 'tuple[list[str], list[str]]':
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            "return cls._unregistered_member(value, 'Unassigned')",
        ]
        for code, (text, cites) in data.items():
            refs = ''.join(f'[{cite}]' for cite in cites)
            enum.append(f'#: {self.wrap_comment(f"{text} {refs}")}\n    CODE_{code} = {code}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(ReplyCode())  # type: ignore[arg-type]
