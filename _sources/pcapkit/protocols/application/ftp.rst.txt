FTP - File Transfer Protocol
============================

:mod:`pcapkit.protocols.application.ftp` contains
:class:`~pcapkit.protocols.application.ftp.FTP` only,
which implements extractor for File Transfer Protocol
(FTP) [*]_.

.. automodule:: pcapkit.protocols.application.ftp
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_FTP_Request

   :bases: TypedDict

   Structure of FTP request packet [:rfc:`959`].

   .. attribute:: type
      :type: Literal['request']

      Packet type.

   .. attribute:: command
      :type: pcapkit.corekit.infoclass.Info

      FTP command.

   .. attribute:: arg
      :type: Optional[str]

      FTP command arguments.

   .. attribute:: raw
      :type:  bytes

      Raw packet data.

.. class:: DataType_FTP_Response

   :bases: TypedDict

   Structure of FTP response packet [:rfc:`959`].

   .. attribute:: type
      :type: Literal['response']

      Packet type.

   .. attribute:: code
      :type: pcapkit.const.ftp.return_code.ReturnCode

      FTP response code.

   .. attribute:: arg
      :type: Optional[str]

      FTP response arguments (messages).

   .. attribute:: mf
      :type: bool

      More fragmented messages flag.

   .. attribute:: raw
      :type:  bytes

      Raw packet data.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol
