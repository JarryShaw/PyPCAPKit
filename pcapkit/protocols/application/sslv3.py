# -*- coding: utf-8 -*-
"""SSLv3 - Secure Sockets Layer version 3
============================================

.. module:: pcapkit.protocols.application.sslv3

:mod:`pcapkit.protocols.application.sslv3` contains
:class:`~pcapkit.protocols.application.sslv3.SSLv3` only, the concrete tier
:class:`TLS <pcapkit.protocols.application.tls.TLS>` delegates to for a
record whose legacy version is ``0x0300``. SSLv3 shares TLS's record-layer
wire format exactly -- the ``0x03xx`` legacy version range it and every TLS
version after it were designed to extend -- so this class contributes
nothing of its own beyond a fixed :attr:`alias` and a narrowed :meth:`id`:
the actual parse is :meth:`TLS._read_tls_record
<pcapkit.protocols.application.tls.TLS._read_tls_record>`, shared by every
tier in the family.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.application.tls import TLS as TLSBase
from pcapkit.protocols.data.application.tls import TLS as Data_TLS
from pcapkit.protocols.schema.application.tls import TLS as Schema_TLS

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

__all__ = ['SSLv3']


class SSLv3(TLSBase, data=Data_TLS, schema=Schema_TLS):
    """This class implements Secure Sockets Layer version 3."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Secure Sockets Layer version 3"]':  # type: ignore[override]
        """Name of current protocol."""
        return 'Secure Sockets Layer version 3'

    @property
    def alias(self) -> 'Literal["SSLv3"]':
        """Acronym of current protocol."""
        return 'SSLv3'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["TLS"], Literal["SSLv3"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('TLS', cls.__name__)  # type: ignore[return-value]

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TLS':
        """Read Secure Sockets Layer version 3.

        Delegates to :meth:`TLS._read_tls_record
        <pcapkit.protocols.application.tls.TLS._read_tls_record>`, shared by
        every tier in the TLS family.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        return self._read_tls_record(length, **kwargs)
