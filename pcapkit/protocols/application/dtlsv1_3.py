# -*- coding: utf-8 -*-
"""DTLSv1_3 - Datagram Transport Layer Security version 1.3
===============================================================

.. module:: pcapkit.protocols.application.dtlsv1_3

:mod:`pcapkit.protocols.application.dtlsv1_3` contains
:class:`~pcapkit.protocols.application.dtlsv1_3.DTLSv1_3` only, the concrete
tier :class:`DTLS <pcapkit.protocols.application.dtls.DTLS>` delegates to
for a record whose legacy version is ``0xFEFD`` [:rfc:`9147`] *and* whose
``ClientHello``/``ServerHello`` negotiates DTLS 1.3 via a
``supported_versions`` extension -- DTLS 1.3 freezes its own legacy-format
records at DTLS 1.2's value for backward compatibility
(:rfc:`9147#section-4.1`), so the record header alone cannot tell the two
apart; see :meth:`DTLS._guess_version
<pcapkit.protocols.application.dtls.DTLS._guess_version>` and
:meth:`SSL._tls_negotiates <pcapkit.protocols.application.ssl.SSL._tls_negotiates>`
for how dispatch resolves it.

**Only DTLS 1.3's legacy-format records are decoded here** -- the
``DTLSPlaintext`` shape every tier in the family shares, which DTLS 1.3
keeps for the records exchanged before a connection has a negotiated epoch
(:rfc:`9147#section-4.1`). The *unified header* format :rfc:`9147#section-4`
introduces once epoch negotiation completes is not decoded by this class or
any other in this family (:issue:`2467`, which depends on this restructure
landing first): its first octet carries no content-type byte at all, so
:meth:`SSL._validate_tls_record
<pcapkit.protocols.application.ssl.SSL._validate_tls_record>` rejects it and
it degrades to :class:`~pcapkit.protocols.misc.raw.Raw` rather than being
misdecoded as a legacy-format record.

DTLS 1.3's legacy-format records share the record-layer wire format every
tier in the family does, so this class contributes nothing of its own
beyond a fixed :attr:`alias` and a narrowed :meth:`id`: the actual parse is
:meth:`DTLS._read_dtls_record
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

__all__ = ['DTLSv1_3']


class DTLSv1_3(DTLSBase, data=Data_DTLS, schema=Schema_DTLS):
    """This class implements Datagram Transport Layer Security version 1.3
    (legacy-format records only; see the module docstring).

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self) -> 'Literal["DTLS 1.3"]':
        """Acronym of current protocol."""
        return 'DTLS 1.3'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["DTLS"], Literal["DTLSv1_3"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('DTLS', cls.__name__)  # type: ignore[return-value]

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DTLS':
        """Read Datagram Transport Layer Security version 1.3 (legacy-format records).

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
