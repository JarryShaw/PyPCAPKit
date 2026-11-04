FTP - File Transfer Protocol
============================

.. module:: pcapkit.protocols.application.ftp
.. module:: pcapkit.protocols.application.ftp.protocol

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.application.ftp.FTP_REQUEST``,
   ``pcapkit.protocols.application.ftp.FTP_RESPONSE`` and
   ``pcapkit.protocols.application.ftp.Type``, with no alias: they are in this module,
   and :mod:`pcapkit.protocols.application.ftp` exports the protocol class alone
   (:issue:`2534`).

:mod:`pcapkit.protocols.application.ftp.protocol` contains
:class:`~pcapkit.protocols.application.ftp.protocol.FTP`,
which implements an extractor for File Transfer Protocol
(FTP) [*]_, the control channel; the data channel is
:class:`~pcapkit.protocols.application.ftp_data.protocol.FTP_DATA`, in
:mod:`pcapkit.protocols.application.ftp_data.protocol`.

.. versionchanged:: 1.5.0

   A command or reply rebuilds byte for byte, its CRLF included, and keeps
   the command's case and any octets that are not UTF-8 as captured. A line
   with no argument and a multi-line reply, whole in one segment or not,
   parse and rebuild as captured (:issue:`1238`, :issue:`1239`,
   :issue:`1240`, :issue:`1241`, :issue:`1303`, :issue:`1333`).

.. versionremoved:: 1.5.0

   ``pcapkit.protocols.application.ftp.FTP_DATA``, with no alias. The class
   moved to :mod:`pcapkit.protocols.application.ftp_data.protocol`, since TCP port 20
   dispatches it and port 21 the control channel -- two protocols, so two
   modules (:issue:`2285`).

.. autoclass:: pcapkit.protocols.application.ftp.protocol.FTP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __index__

   .. automethod:: _make_data

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.application.ftp.protocol.Type
   :members:
   :show-inheritance:

Header Schemas
--------------

.. module:: pcapkit.protocols.application.ftp.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.application.ftp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.application.ftp.schema.FTP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.application.ftp.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.application.ftp``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.application.ftp.data.FTP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ftp.data.Request
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.ftp.data.Response
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol
