FTP_DATA - FTP Data Channel
===========================

.. module:: pcapkit.protocols.application.ftp_data

:mod:`pcapkit.protocols.application.ftp_data` contains
:class:`~pcapkit.protocols.application.ftp_data.FTP_DATA` only,
which implements an extractor for the data channel of File
Transfer Protocol (FTP) [*]_, whose octets it keeps undissected.

.. versionadded:: 1.5.0

   Moved here from :mod:`pcapkit.protocols.application.ftp`, which keeps
   :class:`~pcapkit.protocols.application.ftp.FTP` alone. The control and data
   channels are dispatched separately -- FTP at TCP port 21, the data channel
   at port 20 -- so each is a protocol of its own and gets its own module,
   unlike :class:`~pcapkit.protocols.application.rarp.RARP` and
   :class:`~pcapkit.protocols.application.rarp.DRARP`, which one dispatch
   entry reaches (:issue:`2285`).

.. autoclass:: pcapkit.protocols.application.ftp_data.FTP_DATA
   :no-members:
   :show-inheritance:

   .. autoproperty:: name

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol
