# -*- coding: utf-8 -*-
"""PyShark Support
=====================

.. module:: pcapkit.foundation.engines.pyshark

This module contains the implementation for `PyShark`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyShark: https://kiminewt.github.io/pyshark

"""
import json
import os
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING, cast

from pcapkit.const.pcapng.block_type import BlockType as Enum_BlockType
from pcapkit.foundation.engines.engine import EngineBase
from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
from pcapkit.foundation.engines.pcapng import PCAPNG as PCAPNG_Engine
from pcapkit.foundation.reassembly import ReassemblyManager
from pcapkit.protocols.misc.pcap.header import Header
from pcapkit.utilities.exceptions import FormatError, stacklevel
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import AttributeWarning, PySharkWarning, warn

__all__ = ['PyShark']

if TYPE_CHECKING:
    from typing import IO, Generator, Literal, Optional, Union

    from pyshark.capture.file_capture import FileCapture
    from pyshark.packet.layers.base import BaseLayer
    from pyshark.packet.packet import Packet as PySharkPacket

    from pcapkit.foundation.extraction import Extractor
    from pcapkit.toolkit.pyshark import Captured

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


def _ek_record(line: 'bytes') -> 'Optional[Union[tuple[int, bytes], str]]':
    """Parse a line of :program:`tshark`'s ``-T ek -x -J frame`` output.

    Args:
        line: One line of the output.

    Returns:
        :data:`None` for an index line, which each packet line follows; for a
        packet line, its ``frame.number`` and its frame's captured octets, the
        ``frame_raw`` that ``-x`` adds; otherwise, a phrase saying the line
        cannot be parsed.

    """
    try:
        record = json.loads(line)
        if isinstance(record, dict) and set(record) == {'index'}:
            return None
        layers = record['layers']
        number, octets = layers['frame']['frame_frame_number'], layers['frame_raw']
        if isinstance(number, list):
            number = number[0]
        if isinstance(octets, list):
            octets = octets[0]
        return int(number), bytes.fromhex(octets)
    except (ValueError, LookupError, TypeError):  # not JSON, a field missing, or not text
        return f'gave output it cannot parse: {bytes(line[:80])!r}'


def _linktypes(path: 'str') -> 'Generator[int, None, None]':
    """Read the link type of each packet of a capture file, in order, as the default engine reads it.

    Args:
        path: The PCAP or PCAP-NG file.

    Yields:
        The link type the default engine dissects each packet by. A PCAP file
        has one, in its global header. A PCAP-NG packet takes that of the
        interface it was captured on, among the Interface Description Blocks of
        its own section: an Enhanced or obsolete Packet Block names it by ID, and
        a Simple Packet Block is the first's. These three are the packets the
        default engine counts as frames; every other block is skipped.

    Raises:
        FormatError: If a PCAP-NG block is of no byte order a Section Header
            Block declares, too short for its fields, or a packet block naming
            an interface its section does not describe. A block cut short by
            the end of the file ends the packets instead.

    Note:
        The file is opened at the first packet asked for, and closed at its end,
        or when the generator is closed.

    """
    # length of the field after a block's type and length that names its link
    # type (IDB) or interface (EPB, obsolete Packet Block), by block type
    fields = {
        int(Enum_BlockType.Interface_Description_Block): 2,
        int(Enum_BlockType.Enhanced_Packet_Block): 4,
        int(Enum_BlockType.Packet_Block): 2,
    }  # type: dict[int, int]

    with open(path, 'rb') as file:
        if file.read(4) in PCAP_Engine.MAGIC_NUMBER:
            file.seek(0)
            linktype = int(Header(file).protocol)
            while True:
                yield linktype

        file.seek(0)
        byteorder = None  # type: Optional[Literal['big', 'little']]
        interfaces = []  # type: list[int]
        while True:
            head = file.read(8)
            if head[:4] == PCAPNG_Engine.MAGIC_NUMBER[0]:  # a palindrome, the same in either byte order
                head += file.read(4)
                if len(head) < 12:
                    return
                byteorder = PCAPNG_Engine.BYTE_ORDER_MAGIC.get(head[8:])
                interfaces = []  # an interface ID counts the IDBs of its own section
            elif len(head) < 8:
                return
            if byteorder is None:
                raise FormatError(f'PCAP-NG: block of no known byte order: {head!r}')
            kind, length = int.from_bytes(head[:4], byteorder), int.from_bytes(head[4:8], byteorder)
            size = fields.get(kind, 0)
            if length < len(head) + size + 4:  # the type, length, field, and trailing length
                raise FormatError(f'PCAP-NG: [Block {kind}] invalid block length: {length}')

            field = file.read(size)
            file.seek(length - len(head) - size - 4, os.SEEK_CUR)
            if len(field) < size or len(file.read(4)) < 4:
                return

            if kind == Enum_BlockType.Interface_Description_Block:
                interfaces.append(int.from_bytes(field, byteorder))
            elif kind in (Enum_BlockType.Enhanced_Packet_Block, Enum_BlockType.Packet_Block,
                          Enum_BlockType.Simple_Packet_Block):
                interface = int.from_bytes(field, byteorder)  # 0 for a Simple Packet Block, which has none
                if interface >= len(interfaces):
                    raise FormatError(f'PCAP-NG: [Block {kind}] invalid interface ID: {interface}')
                yield interfaces[interface]


def _frame_layer(packet: 'PySharkPacket') -> 'Optional[BaseLayer]':
    """The ``frame`` layer of a `PyShark`_ packet, or :data:`None` when the record has none.

    Looked up by name, because `PyShark`_ takes the second PDML ``<proto>`` as
    ``frame_info``. On a packet with a comment, that is ``pkt_comment``, which has
    no ``protocols``, and the frame layer is ``layers[0]``. By its source,
    :program:`tshark` 4.2.2 roots a Sysdig event at ``syscall`` and a Netflix
    custom block at ``bblog``, so those records have no ``frame`` layer.

    .. _PyShark: https://kiminewt.github.io/pyshark

    """
    for layer in (packet.frame_info, *packet.layers):
        if layer.layer_name == 'frame':
            return layer
    return None


def _is_packet(packet: 'PySharkPacket') -> 'bool':
    """Whether a `PyShark`_ packet is a packet record, rather than another kind of tshark record.

    :program:`tshark` numbers every record it reads, not only packets: a PCAP-NG
    systemd Journal Export Block, Custom Block or Sysdig Event Block is a frame
    to it, measured with :program:`tshark` 4.6.9. The default engine counts
    Enhanced, Simple and obsolete Packet Blocks only.

    The marker is ``frame.encap_type`` on the record's :func:`_frame_layer`.
    Wireshark adds it for ``REC_TYPE_PACKET`` records only:
    :file:`epan/dissectors/packet-frame.c` lines 1001-1002 in 4.2.2, and 828-890
    in 4.6.9. The summary line is not used, because it differs between those
    versions. A record with no ``frame`` layer is not a packet either.

    .. _PyShark: https://kiminewt.github.io/pyshark

    """
    frame = _frame_layer(packet)
    return frame is not None and 'encap_type' in frame.field_names


class PyShark(EngineBase['PySharkPacket']):
    """PyShark engine support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """
    if TYPE_CHECKING:
        import pyshark

        #: Engine extraction package.
        _expkg: 'pyshark'
        #: Engine extraction temporary storage.
        _extmp: 'FileCapture'
        #: The second :program:`tshark` pass :meth:`_captured` reads captured
        #: octets from, once it is first asked for some.
        _exraw: 'Optional[subprocess.Popen[bytes]]'
        #: Where that pass writes its standard error.
        _exraw_err: 'Optional[IO[bytes]]'
        #: The frame number and octets :meth:`_captured` last read from it.
        _exraw_held: 'Optional[tuple[int, bytes]]'
        #: The link type of each packet of the capture file (see
        #: :func:`_linktypes`), which :meth:`_captured` reads, once it is first
        #: asked for one.
        _exlink: 'Optional[Generator[int, None, None]]'
        #: The count and link type of the packet :meth:`_captured` last read from it.
        _exlink_held: 'Optional[tuple[int, int]]'
        #: Whether reading either has failed, so :meth:`_captured` reads no more.
        _exraw_failed: 'bool'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Engine name.
    __engine_name__ = 'PyShark'

    #: Engine module name.
    __engine_module__ = 'pyshark'

    #: First Python version `PyShark`_ does not work on, as a ``(major, minor)``
    #: pair. Released 0.6 builds its event loop with
    #: ``asyncio.get_event_loop_policy().get_event_loop()``, and Python 3.14 made
    #: :func:`asyncio.get_event_loop` raise :exc:`RuntimeError` when no current
    #: event loop exists instead of quietly creating one.
    PYTHON_CEILING = (3, 14)

    #: :program:`tshark` preferences :meth:`run` overrides, through
    #: ``pyshark``'s ``override_prefs``: IPv4 and IPv6 reassembly off. tshark
    #: reassembles fragments by default and dissects what the datagram carries
    #: at the frame that completes it, so TCP was traced at the last fragment.
    #: The default engine reads each frame as captured, TCP from a first
    #: fragment (:issue:`1612`), and pcapkit's own reassembly is disabled on
    #: this engine.
    #:
    #: Turning tshark's off also changes its TCP analysis, which is not
    #: confined to fragments. Measured with tshark 4.6.9: tshark sizes a
    #: fragmented segment from its first fragment alone, so its sequence
    #: analysis sees a gap after it. Later frames of that stream, fragments or
    #: not, then gain ``tcp.analysis.lost_segment``, and their other
    #: ``tcp.analysis`` fields, ``tcp.completeness``, ``tcp.time_delta`` and
    #: ``tcp.stream.*.contiguity_count`` change. Those fields reach the frame
    #: records :func:`~pcapkit.toolkit.pyshark.packet2dict` builds. But
    #: :func:`~pcapkit.toolkit.pyshark.tcp_traceflow` reads none of them, so
    #: flow tracing is unaffected. The 23 captures under
    #: :file:`examples/captures` carry no fragmented TCP. On them, every field
    #: of every frame is the same either way, except the first and last
    #: fragments of the one fragmented UDP datagram in :file:`ipv6.pcap`.
    OVERRIDE_PREFS = {'ip.defragment': 'FALSE', 'ipv6.defragment': 'FALSE'}  # type: dict[str, str]

    ##########################################################################
    # Class methods.
    ##########################################################################

    @classmethod
    def unsupported_reason(cls) -> 'Optional[str]':
        """Why this engine cannot run here, or :data:`None` when it can.

        Consulted by :meth:`pcapkit.foundation.extraction.Extractor.run` *before*
        the import test, because neither of the two things that stop this engine
        is visible to an import. `PyShark`_ imports perfectly well and then fails
        when it is used, which without this hook escapes from :meth:`run` as a hard
        error rather than degrading to the default engine with a warning.

        **The interpreter.** ``pyshark`` 0.6 does
        ``asyncio.get_event_loop_policy().get_event_loop()`` at
        :file:`pyshark/capture/capture.py:183`, in a fresh interpreter with no
        running loop. Measured on four interpreters: 3.10 and 3.11 return a loop
        silently, 3.12 returns one with a :exc:`DeprecationWarning`, and 3.14
        raises ``RuntimeError: There is no current event loop in thread
        'MainThread'``. Hence :attr:`PYTHON_CEILING` is ``(3, 14)``. Python 3.13 was
        not measured; it is expected to work, since it is on the
        deprecated-but-functional side of that progression, and that expectation
        is the one thing here that is inferred rather than observed.

        **The** :program:`tshark` **binary.** ``pyshark`` is a wrapper around
        Wireshark's command-line tool and does no parsing itself, so it is useless
        without it. The check delegates to ``pyshark``'s own
        ``get_process_path()`` rather than calling :func:`shutil.which`, because
        the two are not equivalent and ``which`` would refuse setups that work:
        ``pyshark`` looks at ``tshark_path`` in its :file:`config.ini` *first*, and
        then at :envvar:`PATH` on POSIX, at both Program Files directories on
        Windows, and at :file:`/Applications/Wireshark.app` on macOS. Asking
        ``pyshark`` gets all of that for free and cannot disagree with what
        ``pyshark`` will do a moment later.

        Note:
            Deliberately **not cached**, and the cost was measured rather than
            assumed: the failing path -- which is the expensive one, since it
            exhausts every candidate -- takes about 290 microseconds with 39
            :envvar:`PATH` entries, against about 120 for a bare
            :func:`shutil.which`. This runs once per
            :class:`~pcapkit.foundation.extraction.Extractor`, not once per frame,
            so it is far below the cost of opening the capture. Caching would trade
            that for an answer about the *environment* that cannot change within
            the process -- so installing Wireshark, or fixing
            :envvar:`PATH`, would not take effect until restart. The Windows path
            does more work than the POSIX one (two Program Files directories, and
            :func:`shutil.which` there would multiply by ``PATHEXT``), but it is
            still a bounded handful of :func:`os.stat` calls.

        Returns:
            A short phrase naming the limitation, or :data:`None`.

        .. _PyShark: https://kiminewt.github.io/pyshark

        """
        if sys.version_info[:2] >= cls.PYTHON_CEILING:
            return (f'pyshark does not support Python '
                    f'{sys.version_info[0]}.{sys.version_info[1]}; it builds its event '
                    'loop with `asyncio.get_event_loop_policy().get_event_loop()`, which '
                    'raises RuntimeError '
                    'from Python 3.14 when no current event loop exists')

        try:
            from pyshark.tshark.tshark import get_process_path  # isort:skip
        except ImportError:
            # Not installed, which is ``Extractor.import_test``'s business -- it
            # reports that case in its own words, and answering here as well would
            # produce two warnings for one problem. An ImportError from a *renamed*
            # upstream helper lands here too, and the engine then simply proceeds
            # without the ``tshark`` check.
            return None

        try:
            get_process_path()
        except Exception as exc:  # pylint: disable=broad-except
            # ``TSharkNotFoundException`` by name, but caught broadly: the whole
            # point is to turn any failure to locate the binary into a reason
            # rather than let it escape, and upstream is free to raise something
            # else. Its own message lists every path it searched, which is exactly
            # what the user needs, so it is quoted rather than summarised.
            return (f'pyshark requires Wireshark\'s `tshark` binary, which pyshark '
                    f'could not find -- {exc}')

        return None

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        import pyshark  # isort:skip

        self._expkg = pyshark
        self._extmp = cast('FileCapture', None)
        self._exraw = None
        self._exraw_err = None
        self._exraw_held = None
        self._exlink = None
        self._exlink_held = None
        self._exraw_failed = False

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :class:`pyshark.FileCapture` to extract PCAP files.

        This method assigns :attr:`self._expkg <PyShark._expkg>`
        as :mod:`pyshark` and :attr:`self._extmp <PyShark._extmp>`
        as an iterator from :class:`pyshark.FileCapture`, with
        :program:`tshark`'s IP reassembly off (:attr:`OVERRIDE_PREFS`).

        The global header is parsed and dumped first, by
        :meth:`self.extractor.record_header <pcapkit.foundation.extraction.Extractor.record_header>`.

        Warns:
            AttributeWarning: Warns under following circumstances:

                * if :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                  and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                  is provided as the PyShark engine does not
                  support such operations.
                * if reassembly is enabled, as the PyShark engine
                  does not support such operation.
                * if :attr:`self.extractor._exctx <pcapkit.foundation.extraction.Extractor._exctx>`
                  is provided, as the PyShark engine does not parse with
                  :mod:`pcapkit`'s own protocol implementations.

        """
        ext = self._extractor

        if ext._exlyr != 'none' or ext._exptl != 'null':
            warn("'Extractor(engine=pyshark)' does not support protocol and layer threshold; "
                 f"'layer={ext._exlyr}' and 'protocol={ext._exptl}' ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if ext._exctx:
            warn("'Extractor(engine=pyshark)' does not parse with pcapkit's own protocol "
                 "implementations, so the parsing context supplied through "
                 "'context=' is ignored",
                 AttributeWarning, stacklevel=stacklevel())

        if ext._flag_r and (ext._ipv4 or ext._ipv6 or ext._tcp):
            ext._flag_r = False
            logger.debug('pyshark: reassembly unsupported, disabling it')
            ext._reasm = ReassemblyManager(ipv4=None, ipv6=None, tcp=None)
            warn("'Extractor(engine=pyshark)' object does not support reassembly; "
                 f"so 'ipv4={ext._ipv4}', 'ipv6={ext._ipv6}' and 'tcp={ext._tcp}' will be ignored",
                 AttributeWarning, stacklevel=stacklevel())

        # setup verbose handler; a packet always has a frame layer, since
        # read_frame skips every record that does not (#1515)
        if ext._flag_v:
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: '  # pylint: disable=protected-access
                f'{cast("BaseLayer", _frame_layer(f)).protocols}'
            )

        # extract global header
        ext.record_header()

        # extract & analyse file
        logger.debug('pyshark: opening %s', ext._ifnm)
        self._extmp = self._expkg.FileCapture(ext._ifnm, keep_packets=False,
                                              override_prefs=dict(self.OVERRIDE_PREFS))

    def read_frame(self) -> 'PySharkPacket':
        """Read frames with PyShark engine.

        A tshark record that is not a packet, such as a PCAP-NG systemd Journal
        Export Block, is skipped. Frames are numbered by count, as the default
        engine numbers them, not by tshark's frame number.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`PCAP.read_frame <pcapkit.foundation.engines.pcap.PCAP.read_frame>`
            for more operational information.

        """
        from pcapkit.toolkit.pyshark import packet2dict, tcp_traceflow
        ext = self._extractor

        # fetch the next PyShark packet that is a packet record
        while True:
            packet = cast('PySharkPacket', self._extmp.next())
            if _is_packet(packet):
                break
            logger.debug('pyshark: skipping tshark frame %s, not a packet record', packet.number)

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

        # trace flows
        if ext._flag_t:
            if ext._tcp:
                data_tf_tcp = tcp_traceflow(packet, count=ext._frnum, captured=self._captured)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            ext._frame.append(packet)

        # return frame record
        return packet

    def _octets_command(self) -> 'list[str]':
        """The command line of the second :program:`tshark` pass :meth:`_captured` reads.

        Returns:
            :program:`tshark`, found as `PyShark`_ finds it, reading the capture
            with the preferences :meth:`run` gives `PyShark`_
            (:attr:`OVERRIDE_PREFS`) and no name resolution, and writing the
            frames :data:`~pcapkit.toolkit.pyshark.OCTETS_FILTER` matches as
            Elasticsearch JSON, one line each, with their captured octets
            (``-x``) and no protocol's fields but the frame's (``-J frame``).

        .. _PyShark: https://kiminewt.github.io/pyshark

        """
        from pyshark.tshark.tshark import get_process_path  # isort:skip

        from pcapkit.toolkit.pyshark import OCTETS_FILTER  # isort:skip

        command = [get_process_path(), '-l', '-n', '-r', self._extractor._ifnm, '-Y', OCTETS_FILTER,
                   '-T', 'ek', '-x', '-J', 'frame']
        for name, value in self.OVERRIDE_PREFS.items():
            command += ['-o', f'{name}:{value}']
        return command

    def _read_octets(self, number: 'int') -> 'Union[bytes, str]':
        """Read the captured octets of a frame from the second :program:`tshark` pass.

        Args:
            number: The frame's ``frame.number``.

        Returns:
            The octets, or a phrase saying why there are none.

        """
        if self._exraw is None:
            self._exraw_err = tempfile.TemporaryFile()  # pylint: disable=consider-using-with
            self._exraw = subprocess.Popen(self._octets_command(), stdin=subprocess.DEVNULL,  # pylint: disable=consider-using-with
                                           stdout=subprocess.PIPE, stderr=self._exraw_err)
        held = self._exraw_held
        while held is None or held[0] < number:
            line = cast('IO[bytes]', self._exraw.stdout).readline()
            if not line:
                status = self._exraw.wait()
                if not status:
                    return f'ended before frame {number}'
                error = cast('IO[bytes]', self._exraw_err)
                error.seek(0)
                last = error.read().decode('utf-8', 'replace').strip().splitlines()[-1:]
                return f'exited with status {status}' + ''.join(f' ({text})' for text in last)
            record = _ek_record(line)
            if isinstance(record, str):
                return record
            if record is not None:
                held = self._exraw_held = record
        if held[0] != number:
            return f'has no frame {number}'
        return held[1]

    def _read_linktype(self, count: 'int') -> 'Union[int, str]':
        """Read the link type the default engine dissects a frame by, from the capture file.

        Args:
            count: The frame's count, as the default engine numbers frames.

        Returns:
            The link type, or a phrase saying why there is none.

        """
        if self._exlink is None:
            self._exlink = _linktypes(self._extractor._ifnm)
        held = self._exlink_held
        while held is None or held[0] < count:
            linktype = next(self._exlink, None)
            if linktype is None:
                return f'has no packet {count}'
            held = self._exlink_held = ((0 if held is None else held[0]) + 1, linktype)
        if held[0] != count:
            return f'was read past packet {count}'
        return held[1]

    def _captured(self, packet: 'PySharkPacket') -> 'Optional[Captured]':
        """Read a frame's link type and octets as the default engine reads them, which the PDML :meth:`run` reads lacks.

        :func:`~pcapkit.toolkit.pyshark.tcp_traceflow` asks for one of a frame
        :data:`~pcapkit.toolkit.pyshark.OCTETS_FILTER` matches only (:issue:`1625`).

        Its link type is the one the default engine dissects it by, read from
        the capture file (see :func:`_linktypes`) for the frame of this engine's
        count, which numbers frames as the default engine does. tshark's
        ``frame.encap_type`` cannot say which it is, as tshark reads several link
        types as one (see :data:`~pcapkit.toolkit.pyshark.ENCAP_TYPE_TO_LINKTYPE`).

        Its captured octets come from a second :program:`tshark` pass over the
        capture (see :meth:`_octets_command`), started on the first request.
        Both passes number frames alike and deliver them in order, so the second
        is read forward to the frame asked for, and the last frame it read is
        kept for the next request. The capture file is read forward likewise. A
        capture with no such frame reads neither.

        Args:
            packet: PyShark packet of the first pass.

        Returns:
            The frame's link type and captured octets; :data:`None` once either
            cannot be read.

        Warns:
            PySharkWarning: When the frame cannot be read: the second pass
                cannot be started, exits with an error, gives output that cannot
                be parsed, or lacks the frame asked for; or the capture file
                cannot be read for the frame's link type. Both are then stopped,
                and this and every later frame is traced as tshark dissects it,
                as before :issue:`1625`, which can disagree with the default
                engine.

        Note:
            The second pass is a process of this engine's own rather than a
            second :class:`pyshark.FileCapture`, for two reasons measured with
            `PyShark`_ 0.6 and :program:`tshark` 4.6.9. Its JSON parser reads
            ``frame.time_epoch``, which a Simple Packet Block lacks, and raises
            :exc:`KeyError`. And each capture it creates sets a new
            :class:`asyncio.SafeChildWatcher` (``Capture._setup_eventloop``), so
            the process of the first is left unreaped once a second exists.

        .. _PyShark: https://kiminewt.github.io/pyshark

        """
        from pcapkit.toolkit.pyshark import Captured  # isort:skip

        if self._exraw_failed:
            return None
        frnum = self._extractor._frnum
        source = ('the capture file, read for the link type of a frame with an AH or IPv6 extension '
                  'header in IPv4,')
        try:
            linktype = self._read_linktype(frnum)
            if isinstance(linktype, str):
                reason = linktype
            else:
                source = ('the second tshark pass, which reads the captured octets of a frame with an AH '
                          'or IPv6 extension header in IPv4,')
                octets = self._read_octets(int(packet.number))
                if isinstance(octets, bytes):
                    return Captured(linktype, octets)
                reason = octets
        except Exception as exc:  # pylint: disable=broad-except
            reason = f'failed: {type(exc).__name__}: {exc}'

        self._exraw_failed = True
        self._stop_captured()
        warn(f'Frame {frnum}: {source} {reason}; this and later such frames are traced as tshark '
             'dissects them, which can disagree with the default engine',
             PySharkWarning, stacklevel=stacklevel())
        return None

    def _stop_captured(self) -> 'None':
        """Stop reading frames as :meth:`_captured` reads them.

        The second :program:`tshark` pass, if it was started, is stopped and
        reaped, and the capture file, if it was opened, closed.

        """
        process, self._exraw = self._exraw, None
        error, self._exraw_err = self._exraw_err, None
        linktypes, self._exlink = self._exlink, None
        try:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()
                cast('IO[bytes]', process.stdout).close()
        finally:
            try:
                if error is not None:
                    error.close()
            finally:
                if linktypes is not None:
                    linktypes.close()

    def close(self) -> 'None':
        """Close engine.

        This method is to be used for closing the engine instance. It is to
        close the engine instance after the extraction process is finished,
        and what :meth:`_captured` reads frames from, if anything.

        """
        try:
            self._extmp.close()
        finally:
            self._stop_captured()
