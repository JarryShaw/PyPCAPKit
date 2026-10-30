# -*- coding: utf-8 -*-
"""TLSv1_3 - Transport Layer Security version 1.3
=====================================================

.. module:: pcapkit.protocols.application.tlsv1_3

:mod:`pcapkit.protocols.application.tlsv1_3` contains
:class:`~pcapkit.protocols.application.tlsv1_3.TLSv1_3` only, the concrete
tier :class:`TLS <pcapkit.protocols.application.tls.TLS>` delegates to for a
record whose legacy version is ``0x0303`` [:rfc:`9846`] *and* whose
``ClientHello``/``ServerHello`` negotiates TLS 1.3 via a
``supported_versions`` extension -- TLS 1.3 freezes its own record-layer
legacy version at TLS 1.2's value for backward compatibility
(:rfc:`9846#section-4.1.3`), so the record header alone cannot tell the two
apart; see :meth:`TLS._guess_version
<pcapkit.protocols.application.tls.TLS._guess_version>` and
:meth:`SSL._tls_negotiates <pcapkit.protocols.application.ssl.SSL._tls_negotiates>`
for how dispatch resolves it.

TLS 1.3 shares the record-layer wire format every tier in the family does,
so this class contributes nothing of its own beyond a fixed :attr:`alias`
and a narrowed :meth:`id`: the actual parse is :meth:`TLS._read_tls_record
<pcapkit.protocols.application.tls.TLS._read_tls_record>`, shared by every
tier in the family. This dissector's scope stops at message-TYPE-level
framing (:issue:`2437`), so TLS 1.3-specific content -- an encrypted
``EncryptedExtensions``, ``Certificate``, or ``Finished``, all of which this
version sends under ``application_data`` rather than their TLS 1.2 content
types -- stays the same opaque :obj:`bytes` every other version's encrypted
content does; nothing in this class decodes differently for being 1.3.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.application.tls import TLS as TLSBase
from pcapkit.protocols.data.application.tls import TLS as Data_TLS
from pcapkit.protocols.schema.application.tls import TLS as Schema_TLS

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

__all__ = ['TLSv1_3']


class TLSv1_3(TLSBase, data=Data_TLS, schema=Schema_TLS):
    """This class implements Transport Layer Security version 1.3."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self) -> 'Literal["TLS 1.3"]':
        """Acronym of current protocol."""
        return 'TLS 1.3'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["TLS"], Literal["TLSv1_3"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('TLS', cls.__name__)  # type: ignore[return-value]

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_TLS':
        """Read Transport Layer Security version 1.3.

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
