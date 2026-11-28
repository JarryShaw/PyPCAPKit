# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.smtp.protocol.SMTP` Vendor Crawlers
================================================================================

.. module:: pcapkit.vendor.smtp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.smtp.protocol.SMTP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`SMTP_Command <pcapkit.vendor.smtp.command.Command>`
     - SMTP Commands [*]_
   * - :class:`SMTP_ReplyCode <pcapkit.vendor.smtp.reply_code.ReplyCode>`
     - SMTP Reply Codes [*]_

.. [*] https://www.rfc-editor.org/rfc/rfc5321#section-4.1.1
.. [*] https://www.rfc-editor.org/rfc/rfc5321#section-4.2.3

"""

from pcapkit.vendor.smtp.command import Command as SMTP_Command
from pcapkit.vendor.smtp.reply_code import ReplyCode as SMTP_ReplyCode

__all__ = ['SMTP_Command', 'SMTP_ReplyCode']
