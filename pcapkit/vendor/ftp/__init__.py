# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.ftp.FTP` Vendor Crawler
====================================================================

.. module:: pcapkit.vendor.ftp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.ftp.FTP` implementations. Available
crawlers include:

.. list-table::

   * - :class:`FTP_Command <pcapkit.vendor.ftp.command.Command>`
     - FTP Commands [*]_
   * - :class:`FTP_ReturnCode <pcapkit.vendor.ftp.return_code.ReturnCode>`
     - FTP Return Codes [*]_

.. [*] https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml#ftp-commands-extensions-2
.. [*] https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

"""

from pcapkit.vendor.ftp.command import Command as FTP_Command
from pcapkit.vendor.ftp.return_code import ReturnCode as FTP_ReturnCode

__all__ = ['FTP_Command', 'FTP_ReturnCode']
