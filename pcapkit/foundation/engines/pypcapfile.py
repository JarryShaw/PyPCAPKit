# -*- coding: utf-8 -*-
"""PyPCAPFile Support
=======================

.. module:: pcapkit.foundation.engines.pypcapfile

This module contains the implementation for `PyPCAPFile`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyPCAPFile: https://github.com/kisom/pypcapfile

"""
import binascii
import ctypes
import struct
import sys
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.io import NamedStream
from pcapkit.foundation.engines.engine import EngineBase
from pcapkit.foundation.reassembly import ReassemblyManager
from pcapkit.utilities.exceptions import FormatError, stacklevel
from pcapkit.utilities.warnings import AttributeWarning, ProtocolWarning, warn

__all__ = ['PyPCAPFile']

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator, Optional

    from pcapfile.structs import __pcap_header__ as PCAPFileHeader
    from pcapfile.structs import pcap_packet as PCAPFilePacket

    from pcapkit.foundation.extraction import Extractor


class PyPCAPFile(EngineBase['PCAPFilePacket']):
    """PyPCAPFile engine support.

    `PyPCAPFile`_ is a pure Python savefile reader. It decodes Ethernet, IPv4,
    TCP and UDP, and nothing else -- in particular there is no IPv6 decoder and
    no PCAP-NG support. Consequently this engine

    * reads PCAP savefiles only, raising
      :exc:`~pcapkit.utilities.exceptions.FormatError` on PCAP-NG,
    * reads the savefile's records itself, into `PyPCAPFile`_'s own packet
      objects, as `PyPCAPFile`_ 0.12.0 drops records the ``default`` engine
      reads -- see :meth:`_read_records`,
    * disables IPv6 reassembly, warning as it does so, while leaving IPv4 and
      TCP reassembly and TCP flow tracing in place, and
    * leaves TCP over IPv6 out of TCP reassembly and flow tracing, with one
      :exc:`~pcapkit.utilities.warnings.AttributeWarning` per capture -- see
      :mod:`pcapkit.toolkit.pypcapfile`.

    The engine stops decoding at the network layer rather than descending into
    the transport layer. `PyPCAPFile`_ decoders *replace* the payload bytes of
    the layer they decode, so descending further would discard the verbatim TCP
    segment that :func:`~pcapkit.toolkit.pypcapfile.tcp_reassembly` needs in
    order to report an exact header/payload split.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """
    if TYPE_CHECKING:
        import pcapfile

        #: Engine extraction package.
        _expkg: 'pcapfile'
        #: Engine extraction temporary storage.
        _extmp: 'Iterator[PCAPFilePacket]'
        #: Data link layer protocol, from the savefile header.
        _dlink: 'Enum_LinkType'
        #: Link layer decoder for this savefile, or :data:`None` when
        #: :mod:`pcapfile` has none for its link layer type.
        _declf: 'Optional[Callable[..., Any]]'

    #: Number of layers to descend while decoding, i.e. link plus network. See
    #: the class docstring for why this stops short of the transport layer.
    LAYERS = 2

    #: First Python version `PyPCAPFile`_ does not work on, as a
    #: ``(major, minor)`` pair. Released 0.12.0 imports :mod:`imp` from
    #: :mod:`pcapfile.linklayer`, and :mod:`imp` was removed in Python 3.12.
    PYTHON_CEILING = (3, 12)

    @classmethod
    def unsupported_reason(cls) -> 'Optional[str]':
        """Why this engine cannot run here, or :data:`None` when it can.

        Consulted by :meth:`pcapkit.foundation.extraction.Extractor.run` *before*
        the import test, because the import test cannot answer this question.
        :mod:`pcapfile`'s top-level package imports perfectly well on Python 3.12
        and newer -- it is :mod:`pcapfile.linklayer` that fails, and
        :mod:`pcapfile.savefile` imports it -- so a guard that only tries
        ``import pcapfile`` is satisfied and the :exc:`ModuleNotFoundError` then
        escapes from :meth:`__init__` as a hard error instead of degrading to the
        default engine with a warning, which is what happens when the package is
        simply absent.

        The version is checked rather than the import attempted so that the answer
        does not depend on which of the package's submodules happens to be
        imported first, and so it is the same answer on a machine that has never
        installed :mod:`pcapfile` at all.

        Returns:
            A short phrase naming the limitation, or :data:`None`.

        """
        if sys.version_info[:2] >= cls.PYTHON_CEILING:
            return (f'pypcapfile does not support Python '
                    f'{sys.version_info[0]}.{sys.version_info[1]}; '
                    'its linklayer module imports `imp`, removed in Python 3.12')
        return None

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Engine name.
    __engine_name__ = 'PyPCAPFile'

    #: Engine module name.
    __engine_module__ = 'pcapfile'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def dlink(self) -> 'Enum_LinkType':
        """Data link layer protocol, as reported by the savefile header."""
        return self._dlink

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        import pcapfile  # isort:skip
        import pcapfile.linklayer  # isort:skip
        import pcapfile.savefile  # isort:skip
        import pcapfile.structs  # isort:skip

        self._expkg = pcapfile
        self._extmp = cast('Iterator[PCAPFilePacket]', None)
        self._dlink = cast('Enum_LinkType', None)
        self._declf = None

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :func:`pcapfile.savefile.load_savefile` to extract PCAP files.

        This method assigns :attr:`self._expkg <PyPCAPFile._expkg>`
        as :mod:`pcapfile` and :attr:`self._extmp <PyPCAPFile._extmp>`
        as an iterator over the lazily generated savefile packets.

        :func:`pcapfile.savefile.load_savefile` loads and validates the savefile
        header. The records are then read by :meth:`_read_records`, not by the
        packet generator it returns, which drops records (see there). Like
        :func:`pcapfile.savefile._read_a_packet` with ``layers=0``,
        :meth:`_read_records` does *not* hand back each frame's bytes verbatim --
        it hexlifies the whole frame into ASCII text and stops there, exactly as
        :mod:`pcapfile` does for any layer at which it runs out of layers left to
        descend. It is :meth:`_decode` that un-hexlifies and then decodes each
        frame to :attr:`LAYERS` depth using :func:`pcapfile.linklayer.clookup` --
        the very call :mod:`pcapfile` makes internally. Doing it this way round is
        what lets the link layer type be inspected (and reported on) *before* the
        first frame is decoded.

        Warns:
            AttributeWarning: Warns under following circumstances:

                * if :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                  and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                  is provided as the PyPCAPFile engine does not
                  support such operations.
                * if IPv6 reassembly is enabled, as :mod:`pcapfile` has no IPv6
                  decoder.
                * if :mod:`pcapfile` has no decoder for the savefile's link layer
                  type, in which case frames are left undecoded.

        Raises:
            FormatError: If the file format is not supported, i.e., not a PCAP
                file. :mod:`pcapfile` reads libpcap savefiles only.

        """
        from pcapkit.foundation.engines.pcap import PCAP  # isort:skip

        ext = self._extractor
        pcapfile = self._expkg

        if ext._exlyr != 'none' or ext._exptl != 'null':
            warn("'Extractor(engine=pypcapfile)' does not support protocol and layer threshold; "
                 f"'layer={ext._exlyr}' and 'protocol={ext._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if ext.magic_number not in PCAP.MAGIC_NUMBER:
            raise FormatError(f'unsupported file format: {ext.magic_number!r}; '
                              'the PyPCAPFile engine reads PCAP savefiles only')

        if ext._flag_r and ext._ipv6:
            ext._ipv6 = False
            ext._reasm = ReassemblyManager(ipv4=ext._reasm.ipv4, ipv6=None, tcp=ext._reasm.tcp)
            warn("'Extractor(engine=pypcapfile)' object does not support IPv6 reassembly; "
                 "so 'ipv6=True' will be ignored", AttributeWarning, stacklevel=stacklevel())

        stream = NamedStream(ext._ifile, ext._ifnm)
        sfile = pcapfile.savefile.load_savefile(stream, layers=0, lazy=True)
        self._dlink = Enum_LinkType.get(sfile.header.ll_type)
        self._declf = self._get_decoder(sfile.header.ll_type)

        # setup verbose handler
        if ext._flag_v:
            from pcapkit.toolkit.pypcapfile import packet2chain  # isort:skip
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {packet2chain(f, data_link=self._dlink)}'  # pylint: disable=protected-access
            )  # pylint: disable=logging-fstring-interpolation

        # extract & analyse file
        self._extmp = self._read_records(stream, sfile.header)

    def read_frame(self) -> 'PCAPFilePacket':
        """Read frames with PyPCAPFile engine.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`PCAP.read_frame <pcapkit.foundation.engines.pcap.PCAP.read_frame>`
            for more operational information.

        """
        from pcapkit.toolkit.pypcapfile import (ipv4_reassembly, packet2dict, tcp_reassembly,
                                                tcp_traceflow)
        ext = self._extractor

        # fetch PyPCAPFile packet
        packet = self._decode(next(self._extmp), ext._frnum + 1)

        # verbose output
        ext._frnum += 1
        ext._vfunc(ext, packet)

        # write plist
        frnum = f'Frame {ext._frnum}'
        if not ext._flag_q:
            info = packet2dict(packet, data_link=self._dlink)
            if ext._flag_f:
                ofile = ext._ofile(f'{ext._ofnm}/{frnum}.{ext._fext}')
                ofile(info, name=frnum)
            else:
                ext._ofile(info, name=frnum)
                ofile = ext._ofile
            ext._offmt = ofile.kind

        # record fragments
        if ext._flag_r:
            # NOTE: IPv6 reassembly is switched off in ``run``, as ``pcapfile``
            # cannot decode IPv6 at all.
            if ext._ipv4:
                data_ipv4 = ipv4_reassembly(packet, count=ext._frnum)
                if data_ipv4 is not None:
                    ext._reasm.ipv4(data_ipv4)
            if ext._tcp:
                data_tcp = tcp_reassembly(packet, count=ext._frnum)
                if data_tcp is not None:
                    ext._reasm.tcp(data_tcp)

        # trace flows
        if ext._flag_t:
            if ext._tcp:
                data_tf_tcp = tcp_traceflow(packet, data_link=self._dlink, count=ext._frnum)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            ext._frame.append(packet)

        # return frame record
        return packet

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _get_decoder(self, linktype: 'int') -> 'Optional[Callable[..., Any]]':
        """Return the :mod:`pcapfile` link layer decoder for a link layer type.

        Args:
            linktype: Link layer type code, from the savefile header.

        Returns:
            The decoder class, or :data:`None` when :mod:`pcapfile` has none.

        Warns:
            AttributeWarning: If no decoder is available, as frames will then be
                left hexlified -- see :meth:`run` -- and no reassembly or flow
                tracing is possible.

        """
        try:
            decoder = self._expkg.linklayer.clookup(linktype)
        except IndexError:  # malformed entry in ``pcapfile.linklayer.__LL_TYPES__``
            decoder = None

        if not callable(decoder):
            warn(f'unrecognised link layer protocol: {self._dlink!r}; frames will be left '
                 'undecoded and all analysis functions ignored', AttributeWarning,
                 stacklevel=stacklevel())
            return None
        return decoder

    def _read_records(self, file: 'NamedStream',
                      header: 'PCAPFileHeader') -> 'Iterator[PCAPFilePacket]':
        """Read the savefile's records, as the ``default`` engine reads them.

        :func:`pcapfile.savefile._read_a_packet` (pypcapfile 0.12.0) drops
        records the ``default`` engine reads, in two ways:

        * It picks the byte order of each record header by testing
          ``hdrp[0].byteorder == 'big'`` -- :class:`bytes` against :class:`str`,
          never true on Python 3. A big-endian record header is unpacked
          little-endian, its byte-swapped capture length overruns the file, and
          the savefile ends at its first record (#1512).
        * It ends the savefile at any record whose frame data is empty or shorter
          than its capture length, so a zero-length record drops itself and every
          record after it, and a truncated final record is dropped (#1571).

        This reads each record in the byte order of the header :mod:`pcapfile`
        loaded, into the :class:`pcapfile.structs.pcap_packet` that function
        builds with ``layers=0`` -- the frame hexlified, pointing at the
        savefile's own header -- so :meth:`_decode` and
        :mod:`pcapkit.toolkit.pypcapfile` see what :mod:`pcapfile` hands them.
        It stops where :class:`~pcapkit.protocols.misc.pcap.frame.Frame` stops,
        at a tail too short for a record header, and keeps a record whose capture
        length runs past the data as that does: the capture length as declared,
        the octets present as the frame.

        Args:
            file: The savefile, just past its header, where
                :func:`pcapfile.savefile.load_savefile` leaves it.
            header: The savefile header :mod:`pcapfile` loaded.

        Yields:
            Undecoded savefile packets, one per record.

        Warns:
            ProtocolWarning: If a record's capture length runs past the data.

        """
        order = '>' if header.byteorder == b'big' else '<'
        hdrp = ctypes.pointer(header)
        number = 0
        while True:
            number += 1
            record = file.read(16)
            if len(record) < 16:
                return
            timestamp, timestamp_us, capture_len, packet_len = struct.unpack(f'{order}IIII', record)
            data = file.read(capture_len)
            if len(data) < capture_len:
                warn(f'PCAP: [Frame {number}] captured length {capture_len} runs past the data, '
                     f'which holds {len(data)} octet(s); kept as captured',
                     ProtocolWarning, stacklevel=stacklevel())
            yield cast('PCAPFilePacket', self._expkg.structs.pcap_packet(
                hdrp, timestamp, timestamp_us, capture_len, packet_len, binascii.hexlify(data),
            ))

    def _decode(self, packet: 'PCAPFilePacket', frnum: 'int') -> 'PCAPFilePacket':
        """Decode a raw savefile packet down to :attr:`LAYERS` depth.

        A new :class:`pcapfile.structs.pcap_packet` is built rather than the
        given one mutated, so that a decoding failure leaves the original intact.

        Args:
            packet: Undecoded savefile packet, i.e. as loaded with ``layers=0``,
                whose :attr:`packet.packet <pcapfile.structs.pcap_packet.packet>`
                is therefore the hexlified frame (see :meth:`run`), not the raw
                bytes.
            frnum: Frame number, for the warning message below.

        Returns:
            The decoded packet, or ``packet`` unchanged when it could not be
            decoded, or holds no octets at all.

        Warns:
            AttributeWarning: If :mod:`pcapfile` could not decode the frame, e.g.
                because the capture is truncated. One bad frame should not abort
                the extraction, but it should not pass silently either.

        """
        # A zero-length record holds nothing to decode, which is not a decoding
        # failure: the ``default`` engine reads one without a warning too.
        if self._declf is None or not packet.packet:
            return packet

        try:
            # ``packet.packet`` is hexlified ASCII text, not raw bytes -- see
            # :meth:`run`. ``self._declf`` (e.g. :class:`pcapfile.protocols
            # .linklayer.ethernet.Ethernet`) unpacks its own header straight out
            # of its first argument via :func:`struct.unpack`, so it must be
            # un-hexlified back to raw bytes first, or every field it decodes
            # comes out garbage despite raising nothing.
            decoded = self._declf(binascii.unhexlify(packet.packet), layers=self.LAYERS - 1)
        except (struct.error, AssertionError, ValueError, IndexError, KeyError) as error:
            warn(f'Frame {frnum}: {self._dlink!r} decoding failed ({error!r}); '
                 'frame left undecoded', AttributeWarning, stacklevel=stacklevel())
            return packet

        return cast('PCAPFilePacket', self._expkg.structs.pcap_packet(
            packet.header, packet.timestamp, packet.timestamp_us,
            packet.capture_len, packet.packet_len, decoded,
        ))
