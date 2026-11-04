# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""SSLv2 - Secure Sockets Layer version 2
============================================

.. module:: pcapkit.protocols.application.sslv2

:mod:`pcapkit.protocols.application.sslv2` holds the dissector,
:class:`~pcapkit.protocols.application.sslv2.protocol.SSLv2`, in
:mod:`~pcapkit.protocols.application.sslv2.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.sslv2.schema` and its data model in
:mod:`~pcapkit.protocols.application.sslv2.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.sslv2.protocol import SSLv2

# Header Schemas
from pcapkit.protocols.application.sslv2.schema import ClientHello as Schema_ClientHello
from pcapkit.protocols.application.sslv2.schema import HandshakeBody as Schema_HandshakeBody
from pcapkit.protocols.application.sslv2.schema import ServerHello as Schema_ServerHello
from pcapkit.protocols.application.sslv2.schema import SSLv2 as Schema_SSLv2
from pcapkit.protocols.application.sslv2.schema import \
    UnknownHandshakeBody as Schema_UnknownHandshakeBody

# Data Models
from pcapkit.protocols.application.sslv2.data import ClientHello as Data_ClientHello
from pcapkit.protocols.application.sslv2.data import ServerHello as Data_ServerHello
from pcapkit.protocols.application.sslv2.data import SSLv2 as Data_SSLv2

__all__ = ['SSLv2']
