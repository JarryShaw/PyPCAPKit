# -*- coding: utf-8 -*-
"""DTLSv1_2 - Datagram Transport Layer Security version 1.2
===============================================================

.. module:: pcapkit.protocols.application.dtlsv1_2

:mod:`pcapkit.protocols.application.dtlsv1_2` contains
:class:`~pcapkit.protocols.application.dtlsv1_2.DTLSv1_2` only, the concrete
tier :class:`DTLS <pcapkit.protocols.application.dtls.DTLS>` delegates to
for a record whose legacy version is ``0xFEFD`` [:rfc:`6347`] and that is
not negotiating DTLS 1.3 via a ``supported_versions`` extension. ``0xFEFD``
is also the legacy version DTLS 1.3 freezes its own legacy-format records
at (:rfc:`9147#section-4.1`), so this tier doubles as the generic fallback
for that ambiguous value, and for any legacy version :class:`DTLS
<pcapkit.protocols.application.dtls.DTLS>`'s dispatch does not otherwise
recognise -- see :meth:`DTLS._guess_version
<pcapkit.protocols.application.dtls.DTLS._guess_version>`.

DTLS 1.2 shares the record-layer wire format every tier in the family does,
so this class contributes nothing of its own beyond a fixed :attr:`alias`
and a narrowed :meth:`id`: the actual parse is :meth:`DTLS._read_dtls_record
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

__all__ = ['DTLSv1_2']


class DTLSv1_2(DTLSBase, data=Data_DTLS, schema=Schema_DTLS):
    """This class implements Datagram Transport Layer Security version 1.2."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self) -> 'Literal["DTLS 1.2"]':
        """Acronym of current protocol."""
        return 'DTLS 1.2'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["DTLS"], Literal["DTLSv1_2"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('DTLS', cls.__name__)  # type: ignore[return-value]

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS':
        """Read Datagram Transport Layer Security version 1.2.

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
