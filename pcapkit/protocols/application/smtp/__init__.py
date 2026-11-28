# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""SMTP - Simple Mail Transfer Protocol
==========================================

.. module:: pcapkit.protocols.application.smtp

:mod:`pcapkit.protocols.application.smtp` holds the dissector,
:class:`~pcapkit.protocols.application.smtp.protocol.SMTP`, in
:mod:`~pcapkit.protocols.application.smtp.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.smtp.schema` and its data model in
:mod:`~pcapkit.protocols.application.smtp.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

.. versionadded:: 1.10.0

"""
from pcapkit.protocols.application.smtp.protocol import SMTP

# Header Schemas
from pcapkit.protocols.application.smtp.schema import SMTP as Schema_SMTP

# Data Models
from pcapkit.protocols.application.smtp.data import SMTP as Data_SMTP
from pcapkit.protocols.application.smtp.data import Command as Data_Command
from pcapkit.protocols.application.smtp.data import MailData as Data_MailData
from pcapkit.protocols.application.smtp.data import Reply as Data_Reply

__all__ = ['SMTP']
