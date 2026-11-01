# -*- coding: utf-8 -*-
"""SSLv3 - Secure Sockets Layer version 3
============================================

.. module:: pcapkit.protocols.application.sslv3

:mod:`pcapkit.protocols.application.sslv3` contains
:class:`~pcapkit.protocols.application.sslv3.SSLv3` only,
which implements an extractor for Secure Sockets Layer
version 3 (SSLv3) [*]_, whose record is the one
:mod:`pcapkit.protocols.application.tls` describes.

Nothing dispatches to :class:`~pcapkit.protocols.application.sslv3.SSLv3`:
an SSLv3 record parses as :class:`~pcapkit.protocols.application.tls.TLS`
with alias ``SSLv3``.

.. [*] https://datatracker.ietf.org/doc/html/rfc6101

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.application.tls import TLS
from pcapkit.protocols.data.application.tls import TLS as Data_TLS
from pcapkit.protocols.schema.application.tls import TLS as Schema_TLS

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['SSLv3']


class SSLv3(TLS, schema=Schema_TLS, data=Data_TLS):
    """This class implements Secure Sockets Layer version 3.

    Dispatch never constructs it: an SSLv3 record parses as
    :class:`~pcapkit.protocols.application.tls.TLS` with
    :attr:`~pcapkit.protocols.application.tls.TLS.alias` ``'SSLv3'``. Like
    :class:`~pcapkit.protocols.link.inarp.InARP` to
    :class:`~pcapkit.protocols.link.arp.ARP`, it narrows :meth:`id` only.

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["SSLv3"]]':  # type: ignore[override]
        """Index ID of the protocol."""
        return ('SSLv3',)
