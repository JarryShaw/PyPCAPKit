FTP - File Transfer Protocol
============================

.. module:: pcapkit.protocols.application.ftp
.. module:: pcapkit.protocols.data.application.ftp

:mod:`pcapkit.protocols.application.ftp` contains
:class:`~pcapkit.protocols.application.ftp.FTP` only,
which implements extractor for File Transfer Protocol
(FTP) [*]_.

.. autoclass:: pcapkit.protocols.application.ftp.FTP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.application.ftp.FTP(type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type

.. autoclass:: pcapkit.protocols.data.application.ftp.Request(type, command, arg, raw)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type
   .. autoattribute:: command
   .. autoattribute:: arg
   .. autoattribute:: raw

.. autoclass:: pcapkit.protocols.data.application.ftp.Response(type, code, arg, mf, raw)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type
   .. autoattribute:: code
   .. autoattribute:: arg
   .. autoattribute:: mf
   .. autoattribute:: raw

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol
