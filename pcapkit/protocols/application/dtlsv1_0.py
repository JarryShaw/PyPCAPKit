# -*- coding: utf-8 -*-
"""DTLSv1_0 - Datagram Transport Layer Security version 1.0
===============================================================

.. module:: pcapkit.protocols.application.dtlsv1_0

:mod:`pcapkit.protocols.application.dtlsv1_0` contains
:class:`~pcapkit.protocols.application.dtlsv1_0.DTLSv1_0` only, the concrete
tier :class:`DTLS <pcapkit.protocols.application.dtls.DTLS>` delegates to
for a record whose legacy version is ``0xFEFF`` [:rfc:`4347`]. DTLS 1.0
shares the record-layer wire format every tier in the family does, so this
class contributes nothing of its own beyond a fixed :attr:`alias` and a
narrowed :meth:`id`: the actual parse is :meth:`DTLS._read_dtls_record
<pcapkit.protocols.application.dtls.DTLS._read_dtls_record>`, shared by
every tier in the family.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.application.dtls import DTLS as DTLSBase
from pcapkit.protocols.data.application.dtls import DTLS as Data_DTLS
from pcapkit.protocols.schema.application.dtls import DTLS as Schema_DTLS

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

__all__ = ['DTLSv1_0']


class DTLSv1_0(DTLSBase, data=Data_DTLS, schema=Schema_DTLS):
    """This class implements Datagram Transport Layer Security version 1.0."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self) -> 'Literal["DTLS 1.0"]':
        """Acronym of current protocol."""
        return 'DTLS 1.0'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["DTLS"], Literal["DTLSv1_0"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('DTLS', cls.__name__)  # type: ignore[return-value]

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS':
        """Read Datagram Transport Layer Security version 1.0.

        Delegates to :meth:`DTLS._read_dtls_record
        <pcapkit.protocols.application.dtls.DTLS._read_dtls_record>`, shared
        by every tier in the DTLS family.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        return self._read_dtls_record(length, **kwargs)
