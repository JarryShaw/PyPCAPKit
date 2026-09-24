# -*- coding: utf-8 -*-
"""Scapy Support
===================

.. module:: pcapkit.foundation.engines.scapy

This module contains the implementation for `Scapy`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _Scapy: https://scapy.net

.. note::

   Constructing this engine imports :mod:`scapy.all`, which is what populates
   `Scapy`_'s layer registries -- see :meth:`Scapy.__init__` for why anything
   narrower silently returns undissected frames.

   One side effect is worth knowing about in advance: :mod:`scapy.all` loads
   :mod:`scapy.layers.dcerpc`, which reaches `Scapy`_'s TLS layer and there
   triggers a ``CryptographyDeprecationWarning`` from :mod:`cryptography` about
   finite-field Diffie-Hellman. It is emitted by any complete registry load, not
   by :mod:`scapy.all` in particular, and it concerns a key-exchange code path
   :mod:`pcapkit` never executes -- but it subclasses :exc:`UserWarning`, not
   :exc:`DeprecationWarning`, so Python's default filters show it.

   :mod:`pcapkit` deliberately does not filter it away. The warning is `Scapy`_'s
   to emit and the consumer's to silence, on the same footing as every other
   category (see :mod:`pcapkit.utilities.warnings`); hiding a third-party
   deprecation notice from inside a constructor would suppress the only advance
   warning that a future :mod:`cryptography` release breaks `Scapy`_'s TLS layer.
   To silence it, filter it as usual::

       import warnings

       from cryptography.utils import CryptographyDeprecationWarning

       warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

"""
from typing import TYPE_CHECKING, cast

from pcapkit.foundation.engines.engine import EngineBase
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import AttributeWarning, warn

__all__ = ['Scapy']

if TYPE_CHECKING:
    from typing import Iterator

    from scapy.packet import Packet as ScapyPacket

    from pcapkit.foundation.extraction import Extractor

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class Scapy(EngineBase['ScapyPacket']):
    """Scapy engine support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """
    if TYPE_CHECKING:
        import scapy.all

        #: Engine extraction package.
        _expkg: 'scapy.all'
        #: Engine extraction temporary storage.
        _extmp: 'Iterator[ScapyPacket]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Engine name.
    __engine_name__ = 'Scapy'

    #: Engine module name.
    __engine_module__ = 'scapy'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        """Initialise the engine.

        Args:
            extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

        """
        # NOTE: :mod:`scapy.all`, not :mod:`scapy.sendrecv`, and the difference is
        # load-bearing rather than cosmetic. Scapy dispatches on two registries that
        # exist only as *import side effects* of its layer modules: ``conf.l2types``,
        # mapping a capture's link type onto a link-layer class, and the
        # ``bind_layers`` payload table. ``scapy/__init__.py`` fills in neither, so
        # importing just the sniffing submodule leaves both empty --
        # :class:`~scapy.utils.PcapReader` then cannot map even link type 1 (plain
        # Ethernet), writes ``unknown LL type [1]/[0x1]`` to stderr and returns every
        # frame as one opaque :class:`~scapy.packet.Raw` layer. Nothing raises, so the
        # engine used to deliver no dissection whatsoever and announce it only on
        # stderr (#406).
        #
        # Naming the layer modules individually is not a cheaper way to the same
        # place: it repairs the link layer and leaves the payload table short, so
        # ``dhcp.pcapng`` still comes back as ``Ethernet / IP / UDP / Raw`` rather
        # than ``... / UDP / BOOTP / DHCP options``. Enumerating them here would also
        # go stale silently -- a link or payload type added by a later scapy would
        # regress to ``Raw`` with no error -- whereas :mod:`scapy.all` defers to
        # ``conf.load_layers``, which scapy itself keeps current. The cost is the
        # layer loading, not the façade: importing :mod:`scapy.layers.all` alone
        # measures the same, so there is no complete-but-cheaper option to prefer.
        #
        # This stays inside ``__init__`` rather than moving to module scope so that
        # ``import pcapkit`` does not pay for it; only callers who actually select
        # this engine do. And it is bound to :attr:`_expkg`, the attribute
        # :meth:`run` calls ``sniff`` on, rather than left as a bare side-effecting
        # import -- an import whose value is used cannot be dropped later as unused,
        # which is how this class of bug comes back.
        from scapy import all as scapy  # isort:skip

        self._expkg = scapy
        self._extmp = cast('Iterator[ScapyPacket]', None)

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :func:`scapy.sendrecv.sniff` to extract PCAP files.

        This method assigns :attr:`self._extmp <Scapy._extmp>` as an iterator
        from :func:`scapy.sendrecv.sniff`, reached through
        :attr:`self._expkg <Scapy._expkg>` -- which :meth:`__init__` binds to
        :mod:`scapy.all`, since that is the import that populates the layer
        registries ``sniff`` needs to dissect anything.

        Warns:
            AttributeWarning: If :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                is provided as the Scapy engine currently does not support such operations;
                or if :attr:`self.extractor._exctx <pcapkit.foundation.extraction.Extractor._exctx>`
                is provided, as the Scapy engine does not parse with :mod:`pcapkit`'s own
                protocol implementations.

        """
        ext = self._extractor

        if ext._exlyr != 'none' or ext._exptl != 'null':
            warn("'Extractor(engine=scapy)' does not support protocol and layer threshold; "
                 f"'layer={ext._exlyr}' and 'protocol={ext._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if ext._exctx:
            warn("'Extractor(engine=scapy)' does not parse with pcapkit's own protocol "
                 "implementations, so the parsing context supplied through "
                 "'context=' is ignored",
                 AttributeWarning, stacklevel=stacklevel())

        # setup verbose handler
        if ext._flag_v:
            from pcapkit.toolkit.scapy import packet2chain  # isort:skip
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {packet2chain(f)}'  # pylint: disable=protected-access
            )

        # extract & analyse file
        logger.debug('scapy: sniffing %s', ext._ifnm)
        self._extmp = iter(self._expkg.sniff(offline=ext._ifnm))

    def read_frame(self) -> 'ScapyPacket':
        """Read frames with Scapy engine.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`PCAP.read_frame <pcapkit.foundation.engines.pcap.PCAP.read_frame>`
            for more operational information.

        """
        from pcapkit.toolkit.scapy import (ipv4_reassembly, ipv6_reassembly, packet2dict,
                                           tcp_reassembly, tcp_traceflow)
        ext = self._extractor

        # fetch Scapy packet
        packet = next(self._extmp)

        # verbose output
        ext._frnum += 1
        ext._vfunc(ext, packet)

        # write plist
        frnum = f'Frame {ext._frnum}'
        if not ext._flag_q:
            info = packet2dict(packet)
            if ext._flag_f:
                ofile = ext._ofile(f'{ext._ofnm}/{frnum}.{ext._fext}')
                ofile(info, name=frnum)
            else:
                ext._ofile(info, name=frnum)

        # record fragments
        if ext._flag_r:
            if ext._ipv4:
                data_ipv4 = ipv4_reassembly(packet, count=ext._frnum)
                if data_ipv4 is not None:
                    ext._reasm.ipv4(data_ipv4)
            if ext._ipv6:
                data_ipv6 = ipv6_reassembly(packet, count=ext._frnum)
                if data_ipv6 is not None:
                    ext._reasm.ipv6(data_ipv6)
            if ext._tcp:
                data_tcp = tcp_reassembly(packet, count=ext._frnum)
                if data_tcp is not None:
                    ext._reasm.tcp(data_tcp)

        # trace flows
        if ext._flag_t:
            if ext._tcp:
                data_tf_tcp = tcp_traceflow(packet, count=ext._frnum)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            # setattr(packet, 'packet2chain', packet2chain)
            ext._frame.append(packet)

        # return frame record
        return packet
