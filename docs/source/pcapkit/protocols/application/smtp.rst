SMTP - Simple Mail Transfer Protocol
====================================

.. module:: pcapkit.protocols.application.smtp
.. module:: pcapkit.protocols.application.smtp.protocol

:mod:`pcapkit.protocols.application.smtp.protocol` contains
:class:`~pcapkit.protocols.application.smtp.protocol.SMTP`, which implements an
extractor for the Simple Mail Transfer Protocol (SMTP) [:rfc:`5321`] at TCP
port 25, and for Message Submission [:rfc:`6409`], the same protocol at TCP port
587. Its lines are read through :mod:`pcapkit.utilities.lines`, which FTP shares.

.. versionadded:: 1.10.0

.. autoclass:: pcapkit.protocols.application.smtp.protocol.SMTP
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: length

   .. rubric:: Methods

   .. automethod:: read
   .. automethod:: make

   .. rubric:: Data Models

   .. automethod:: __index__

   .. rubric:: Utilities

   .. automethod:: _make_data

Auxiliary Data
--------------

.. autoclass:: pcapkit.protocols.application.smtp.protocol.Type
   :members:
   :show-inheritance:

Header Schemas
--------------

.. module:: pcapkit.protocols.application.smtp.schema

.. autoclass:: pcapkit.protocols.application.smtp.schema.SMTP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.application.smtp.data

.. autoclass:: pcapkit.protocols.application.smtp.data.SMTP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.smtp.data.Command
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.smtp.data.Reply
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.smtp.data.MailData
   :members:
   :show-inheritance:

Constants
---------

.. module:: pcapkit.protocols.application.smtp.const

.. autodata:: pcapkit.protocols.application.smtp.const.SMTP_COMMAND
   :no-value:

.. autodata:: pcapkit.protocols.application.smtp.const.SMTP_REPLY
   :no-value:
