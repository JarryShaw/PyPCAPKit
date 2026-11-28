# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.smtp.protocol.SMTP` Constant Enumerations
======================================================================================

.. module:: pcapkit.const.smtp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.smtp.protocol.SMTP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`SMTP_Command <pcapkit.const.smtp.command.Command>`
     - SMTP Commands [*]_
   * - :class:`SMTP_ReplyCode <pcapkit.const.smtp.reply_code.ReplyCode>`
     - SMTP Reply Codes [*]_

.. [*] https://www.rfc-editor.org/rfc/rfc5321#section-4.1.1
.. [*] https://www.rfc-editor.org/rfc/rfc5321#section-4.2.3

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.smtp.command import Command as SMTP_Command
    from pcapkit.const.smtp.reply_code import ReplyCode as SMTP_ReplyCode

__all__ = ['SMTP_Command', 'SMTP_ReplyCode']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'SMTP_Command': ('command', 'Command'),
    'SMTP_ReplyCode': ('reply_code', 'ReplyCode'),
})
