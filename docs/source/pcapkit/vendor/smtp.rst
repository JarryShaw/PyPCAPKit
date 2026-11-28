==================================================================================
:class:`~pcapkit.protocols.application.smtp.protocol.SMTP` Vendor Crawlers
==================================================================================

.. module:: pcapkit.vendor.smtp

.. list-table::

   * - :class:`SMTP_Command <pcapkit.vendor.smtp.command.Command>`
     - SMTP Commands [*]_
   * - :class:`SMTP_ReplyCode <pcapkit.vendor.smtp.reply_code.ReplyCode>`
     - SMTP Reply Codes [*]_

.. versionadded:: 1.10.0

.. note::

   Neither crawler crawls. No registry lists the SMTP commands or reply codes:
   :rfc:`5321` gives them in its text, so each is transcribed into the ``DATA``
   mapping of its module, and neither class defines a ``LINK``.

SMTP Command
============

.. module:: pcapkit.vendor.smtp.command

Generates :class:`pcapkit.const.smtp.command.Command`.

.. autoclass:: pcapkit.vendor.smtp.command.Command
   :show-inheritance:

SMTP Reply Code
===============

.. module:: pcapkit.vendor.smtp.reply_code

Generates :class:`pcapkit.const.smtp.reply_code.ReplyCode`.

.. autoclass:: pcapkit.vendor.smtp.reply_code.ReplyCode
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.rfc-editor.org/rfc/rfc5321#section-4.1.1
.. [*] https://www.rfc-editor.org/rfc/rfc5321#section-4.2.3
