# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.ftp.FTP` Constant Enumerations
===========================================================================

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.ftp.FTP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`FTP_Command <pcapkit.const.ftp.command.Command>`
     - FTP Commands [*]_
   * - :class:`FTP_ReturnCode <pcapkit.const.ftp.return_code.ReturnCode>`
     - FTP Return Codes [*]_

.. [*] https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml#ftp-commands-extensions-2
.. [*] https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

"""

from pcapkit.const.ftp.command import Command as FTP_Command
from pcapkit.const.ftp.return_code import ReturnCode as FTP_ReturnCode

__all__ = ['FTP_Command', 'FTP_ReturnCode']
