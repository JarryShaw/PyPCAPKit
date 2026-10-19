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

.. versionchanged:: 1.5.0

   Neither :meth:`Command._missing_ <pcapkit.const.ftp.command.Command._missing_>` nor
   :meth:`Command.get() <pcapkit.const.ftp.command.Command.get>` mints a member
   (:issue:`860`): only IANA-registered values are members, and a new one is created
   through :meth:`~pcapkit.const.ftp.command.Command.register`, which can supply the
   ``feat``, ``desc``, ``type`` and ``conf`` a bare wire command word carries none of. A
   minted member had each of them at its default.

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

This module contains the constant enumeration for **FTP Server Return Code**,
which is automatically generated from :class:`pcapkit.vendor.ftp.return_code.ReturnCode`.

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
