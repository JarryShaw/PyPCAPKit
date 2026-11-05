# -*- coding: utf-8 -*-
"""FTP_DATA - FTP Data Channel
=================================

.. module:: pcapkit.protocols.application.ftp_data.protocol

:mod:`pcapkit.protocols.application.ftp_data.protocol` holds
:class:`~pcapkit.protocols.application.ftp_data.protocol.FTP_DATA`, the extractor
for the data channel of the File Transfer Protocol (FTP) [*]_, whose octets it
keeps undissected.

.. [*] https://en.wikipedia.org/wiki/File_Transfer_Protocol

.. versionadded:: 1.5.0

   Moved here from :mod:`pcapkit.protocols.application.ftp.protocol`, which keeps
   :class:`~pcapkit.protocols.application.ftp.protocol.FTP` alone. The control and data
   channels are dispatched separately -- FTP at TCP port 21, the data channel
   at port 20 -- so each is a protocol of its own and gets its own module
   (:issue:`2285`).

"""
from typing import TYPE_CHECKING

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.misc.raw.protocol import Raw

if TYPE_CHECKING:
    from typing_extensions import Literal

    from pcapkit.const.reg.apptype.tcp import TCP as AppType_TCP

__all__ = ['FTP_DATA']

#: The TCP port registry :meth:`FTP_DATA.__index__` reads its port from, resolved
#: there rather than imported, as ``import pcapkit`` leaves it unloaded
#: (:issue:`1538`), so its first import holds
#: :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_TCP: 'ModuleDescriptor[AppType_TCP]' = ModuleDescriptor('pcapkit.const.reg.apptype.tcp', 'TCP')


class FTP_DATA(Application, Raw):  # pylint: disable=abstract-method
    """This class implements FTP data channel transmission.

    The layer base :class:`~pcapkit.protocols.application.application.Application`
    comes first, for ``layer == 'Application'``, then the parsing base
    :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, which keeps the channel's octets
    undissected. See :doc:`/contributing/conventions/protocol-layer-placement`.

    .. versionchanged:: 1.5.0

       Derives from :class:`~pcapkit.protocols.application.application.Application`
       as well as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, so its layer is
       ``'Application'``, where it was :obj:`None`, and its ``__index__`` became
       :meth:`Application.__index__
       <pcapkit.protocols.application.application.Application.__index__>`,
       raising :exc:`~pcapkit.utilities.exceptions.IntError` where it had raised
       :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` (:issue:`2285`).

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    def name(self) -> 'Literal["FTP_DATA"]':  # type: ignore[override]
        """Name of current protocol."""
        return 'FTP_DATA'

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'int':  # type: ignore[override]
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_ service names and
            port numbers: TCP port 20, the port of
            :attr:`TCP.ftp_data <pcapkit.const.reg.apptype.tcp.TCP.ftp_data>` as
            an :class:`int`, which
            :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>`
            dispatches here (:ref:`registry-protocol-index`).

        .. _IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

        .. versionchanged:: 1.6.0

           Returns TCP port 20, where it raised
           :exc:`~pcapkit.utilities.exceptions.IntError` (:issue:`2627`).

        """
        return int(_TCP.klass.ftp_data)  # type: ignore[call-overload]
