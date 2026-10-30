# -*- coding: utf-8 -*-
"""TLSv1_0 - Transport Layer Security version 1.0
=====================================================

.. module:: pcapkit.protocols.application.tlsv1_0

:mod:`pcapkit.protocols.application.tlsv1_0` contains
:class:`~pcapkit.protocols.application.tlsv1_0.TLSv1_0` only, the concrete
tier :class:`TLS <pcapkit.protocols.application.tls.TLS>` delegates to for a
record whose legacy version is ``0x0301`` [:rfc:`2246`]. TLS 1.0 shares the
record-layer wire format every tier in the family does, so this class
contributes nothing of its own beyond a fixed :attr:`alias` and a narrowed
:meth:`id`: the actual parse is :meth:`TLS._read_tls_record
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

__all__ = ['TLSv1_0']


class TLSv1_0(TLSBase, data=Data_TLS, schema=Schema_TLS):
    """This class implements Transport Layer Security version 1.0."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self) -> 'Literal["TLS 1.0"]':
        """Acronym of current protocol."""
        return 'TLS 1.0'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["TLS"], Literal["TLSv1_0"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('TLS', cls.__name__)  # type: ignore[return-value]

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TLS':
        """Read Transport Layer Security version 1.0.

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
