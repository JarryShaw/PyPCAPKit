==============================================================================
:class:`~pcapkit.protocols.application.ftp.protocol.FTP` Constant Enumerations
==============================================================================

.. module:: pcapkit.const.ftp

.. list-table::

   * - :class:`FTP_Command <pcapkit.const.ftp.command.Command>`
     - FTP Commands [*]_
   * - :class:`FTP_ReturnCode <pcapkit.const.ftp.return_code.ReturnCode>`
     - FTP Return Codes [*]_

FTP Command
===========

.. module:: pcapkit.const.ftp.command

Generated from :class:`pcapkit.vendor.ftp.command.Command`, with the companion
:class:`~pcapkit.const.ftp.command.FEATCode`: the ``FEAT`` response keywords that
the same IANA registry's ``FEAT code`` column names (:rfc:`5797#section-3`).

.. versionchanged:: 1.5.0

   Neither :meth:`Command._missing_ <pcapkit.const.ftp.command.Command._missing_>` nor
   :meth:`Command.get() <pcapkit.const.ftp.command.Command.get>` mints a member
   (:issue:`860`): only IANA-registered values are members, and
   :meth:`~pcapkit.const.ftp.command.Command.register` adds a new one.

   :meth:`Command.get() <pcapkit.const.ftp.command.Command.get>` refuses a
   non-:class:`str` ``key`` with :exc:`~pcapkit.utilities.exceptions.EnumValueError`, with
   or without ``default`` (:issue:`1824`). ``get(42)`` and ``get(None)`` raised
   :exc:`AttributeError` from ``key.upper()``, and ``get(b'ABOR')`` returned an
   unregistered member whose name and value were both the :class:`bytes` object.

.. autoclass:: pcapkit.const.ftp.command.Command
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __new__, __repr__

.. autoclass:: pcapkit.const.ftp.command.FEATCode
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.const.ftp.command.CommandType
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.const.ftp.command.ConformanceRequirement
   :members:
   :undoc-members:
   :show-inheritance:

FTP Server Return Code
============================

.. module:: pcapkit.const.ftp.return_code

Generated from :class:`pcapkit.vendor.ftp.return_code.ReturnCode`.

.. autoclass:: pcapkit.const.ftp.return_code.ReturnCode
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __new__, __repr__, __str__

.. autoclass:: pcapkit.const.ftp.return_code.ResponseKind
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: pcapkit.const.ftp.return_code.GroupingInformation
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml#ftp-commands-extensions-2
.. [*] https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
