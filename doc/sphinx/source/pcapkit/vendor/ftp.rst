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

.. automodule:: pcapkit.vendor.ftp.command
   :no-members:

.. autoclass:: pcapkit.vendor.ftp.command.Command
   :noindex:
   :members: LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.ftp.return_code
   :no-members:

.. autoclass:: pcapkit.vendor.ftp.return_code.ReturnCode
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml#ftp-commands-extensions-2
.. [*] https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
