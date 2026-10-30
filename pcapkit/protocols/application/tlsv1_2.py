# -*- coding: utf-8 -*-
"""TLSv1_2 - Transport Layer Security version 1.2
=====================================================

.. module:: pcapkit.protocols.application.tlsv1_2

:mod:`pcapkit.protocols.application.tlsv1_2` contains
:class:`~pcapkit.protocols.application.tlsv1_2.TLSv1_2` only, the concrete
tier :class:`TLS <pcapkit.protocols.application.tls.TLS>` delegates to for a
record whose legacy version is ``0x0303`` [:rfc:`5246`] and that is not
negotiating TLS 1.3 via a ``supported_versions`` extension. ``0x0303`` is
also the legacy version TLS 1.3 freezes its own records at
(:rfc:`9846#section-4.1.3`), so this tier doubles as the generic fallback for
that ambiguous value, and for any legacy version :class:`TLS
<pcapkit.protocols.application.tls.TLS>`'s dispatch does not otherwise
recognise -- see :meth:`TLS._guess_version
<pcapkit.protocols.application.tls.TLS._guess_version>`.

TLS 1.2 shares the record-layer wire format every tier in the family does,
so this class contributes nothing of its own beyond a fixed :attr:`alias`
and a narrowed :meth:`id`: the actual parse is :meth:`TLS._read_tls_record
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

__all__ = ['TLSv1_2']


class TLSv1_2(TLSBase, data=Data_TLS, schema=Schema_TLS):
    """This class implements Transport Layer Security version 1.2."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self) -> 'Literal["TLS 1.2"]':
        """Acronym of current protocol."""
        return 'TLS 1.2'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["TLS"], Literal["TLSv1_2"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('TLS', cls.__name__)  # type: ignore[return-value]

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TLS':
        """Read Transport Layer Security version 1.2.

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
