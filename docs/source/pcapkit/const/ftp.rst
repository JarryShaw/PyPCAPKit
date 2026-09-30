=====================================================================
:class:`~pcapkit.protocols.application.ftp.FTP` Constant Enumerations
=====================================================================

.. module:: pcapkit.const.ftp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.ftp.FTP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`FTP_Command <pcapkit.const.ftp.command.Command>`
     - FTP Commands [*]_
   * - :class:`FTP_ReturnCode <pcapkit.const.ftp.return_code.ReturnCode>`
     - FTP Return Codes [*]_

FTP Command
===========

.. module:: pcapkit.const.ftp.command

This module contains the constant enumeration for **FTP Command**, which is
automatically generated from :class:`pcapkit.vendor.ftp.command.Command`, plus the
companion :class:`~pcapkit.const.ftp.command.FEATCode` enumeration it also declares --
the ``FEAT`` response keywords the ``FEAT code`` column of the same IANA registry
names, c.f., :rfc:`5797#section-3`.

.. autoclass:: pcapkit.const.ftp.command.Command
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.const.ftp.command.FEATCode
   :members:
   :undoc-members:
   :show-inheritance:

FTP Server Return Code
============================

.. module:: pcapkit.const.ftp.return_code

This module contains the constant enumeration for **FTP Server Return Code**,
which is automatically generated from :class:`pcapkit.vendor.ftp.return_code.ReturnCode`.

.. autoclass:: pcapkit.const.ftp.return_code.ReturnCode
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml#ftp-commands-extensions-2
.. [*] https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
