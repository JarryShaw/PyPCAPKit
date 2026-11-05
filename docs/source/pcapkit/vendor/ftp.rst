========================================================================
:class:`~pcapkit.protocols.application.ftp.protocol.FTP` Vendor Crawlers
========================================================================

.. module:: pcapkit.vendor.ftp

.. list-table::

   * - :class:`FTP_Command <pcapkit.vendor.ftp.command.Command>`
     - FTP Commands [*]_
   * - :class:`FTP_ReturnCode <pcapkit.vendor.ftp.return_code.ReturnCode>`
     - FTP Return Codes [*]_

FTP Command
===========

.. module:: pcapkit.vendor.ftp.command

Generates :class:`pcapkit.const.ftp.command.Command`.

.. autoclass:: pcapkit.vendor.ftp.command.Command
   :members: LINK, process
   :show-inheritance:

FTP Server Return Code
======================

.. module:: pcapkit.vendor.ftp.return_code

Generates :class:`pcapkit.const.ftp.return_code.ReturnCode`.

.. autoclass:: pcapkit.vendor.ftp.return_code.ReturnCode
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml#ftp-commands-extensions-2
.. [*] https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
