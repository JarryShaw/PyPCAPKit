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

.. automodule:: pcapkit.const.ftp.command
   :no-members:

.. data:: pcapkit.const.ftp.command.Command
   :type: defaultInfo[CommandType]

   FTP commands.

.. autoclass:: pcapkit.const.ftp.command.CommandType
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. autoclass:: pcapkit.const.ftp.command.defaultInfo
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. automodule:: pcapkit.const.ftp.return_code
   :no-members:

.. autoclass:: pcapkit.const.ftp.return_code.ReturnCode
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml#ftp-commands-extensions-2
.. [*] https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
