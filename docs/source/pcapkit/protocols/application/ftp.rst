FTP - File Transfer Protocol
============================

.. module:: pcapkit.protocols.application.ftp

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

   .. automethod:: _make_data

.. autoclass:: pcapkit.protocols.application.ftp.FTP_DATA
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.application.ftp.Type
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.application.ftp

.. autoclass:: pcapkit.protocols.schema.application.ftp.FTP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.application.ftp

.. autoclass:: pcapkit.protocols.data.application.ftp.FTP
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.application.ftp.Request
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.application.ftp.Response
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol
