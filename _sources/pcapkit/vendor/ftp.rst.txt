==============================================================
:class:`~pcapkit.protocols.application.ftp.FTP` Vendor Crawler
==============================================================

.. module:: pcapkit.vendor.ftp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.ftp.FTP` implementations. Available
crawlers include:

.. list-table::

   * - :class:`FTP_Command <pcapkit.vendor.ftp.command.Command>`
     - FTP Commands [*]_
   * - :class:`FTP_ReturnCode <pcapkit.vendor.ftp.return_code.ReturnCode>`
     - FTP Return Codes [*]_

FTP Command
===========

.. module:: pcapkit.vendor.ftp.command

This module contains the vendor crawler for **FTP Command**,
which is automatically generating :class:`pcapkit.const.ftp.command.Command`.

.. autoclass:: pcapkit.vendor.ftp.command.Command
   :members: LINK
   :show-inheritance:

FTP Server Return Code
======================

.. module:: pcapkit.vendor.ftp.return_code

This module contains the vendor crawler for **FTP Server Return Code**,
which is automatically generating :class:`pcapkit.const.ftp.return_code.ReturnCode`.

.. autoclass:: pcapkit.vendor.ftp.return_code.ReturnCode
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml#ftp-commands-extensions-2
.. [*] https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
