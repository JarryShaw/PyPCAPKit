# -*- coding: utf-8 -*-
"""PyShark Support
=====================

.. module:: pcapkit.foundation.engines.pyshark

This module contains the implementation for `PyShark`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyShark: https://kiminewt.github.io/pyshark

"""
import sys
from typing import TYPE_CHECKING, cast

from pcapkit.foundation.engines.engine import EngineBase as Engine
from pcapkit.foundation.reassembly import ReassemblyManager
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.logging import get_logger
from pcapkit.utilities.warnings import AttributeWarning, warn

__all__ = ['PyShark']

if TYPE_CHECKING:
    from typing import Optional

    from pyshark.capture.file_capture import FileCapture
    from pyshark.packet.packet import Packet as PySharkPacket

    from pcapkit.foundation.extraction import Extractor

#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class PyShark(Engine['PySharkPacket']):
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
        not available on the machine this was measured on; it is expected to work,
        since it is on the deprecated-but-functional side of that progression, and
        that expectation is the one thing here that is inferred rather than
        observed.

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
            # as it did before this check existed.
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

        super().__init__(extractor)

    ##########################################################################
    # Methods.
    ##########################################################################

    def run(self) -> 'None':
        """Call :class:`pyshark.FileCapture` to extract PCAP files.

        This method assigns :attr:`self._expkg <PyShark._expkg>`
        as :mod:`pyshark` and :attr:`self._extmp <PyShark._extmp>`
        as an iterator from :class:`pyshark.FileCapture`.

        Warns:
            AttributeWarning: Warns under following circumstances:

                * if :attr:`self.extractor._exlyr <pcapkit.foundation.extraction.Extractor._exlyr>`
                  and/or :attr:`self.extractor._exptl <pcapkit.foundation.extraction.Extractor._exptl>`
                  is provided as the PyShark engine currently does not
                  support such operations.
                * if reassembly is enabled, as the PyShark engine currently
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

        # setup verbose handler
        if ext._flag_v:
            ext._vfunc = lambda e, f: print(
                f'Frame {e._frnum:>3d}: {f.frame_info.protocols}'  # pylint: disable=protected-access
            )

        # extract & analyse file
        logger.debug('pyshark: opening %s', ext._ifnm)
        self._extmp = self._expkg.FileCapture(ext._ifnm, keep_packets=False)

    def read_frame(self) -> 'PySharkPacket':
        """Read frames with PyShark engine.

        Returns:
            Parsed frame instance.

        See Also:
            Please refer to :meth:`PCAP.read_frame <pcapkit.foundation.engines.pcap.PCAP.read_frame>`
            for more operational information.

        """
        from pcapkit.toolkit.pyshark import packet2dict, tcp_traceflow
        ext = self._extractor

        # fetch PyShark packet
        packet = cast('PySharkPacket', self._extmp.next())

        # verbose output
        ext._frnum = int(packet.number)
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
                ofile = ext._ofile
            ext._offmt = ofile.kind

        # trace flows
        if ext._flag_t:
            if ext._tcp:
                data_tf_tcp = tcp_traceflow(packet)
                if data_tf_tcp is not None:
                    ext._trace.tcp(data_tf_tcp)

        # record frames
        if ext._flag_d:
            # setattr(packet, 'packet2dict', packet2dict)
            ext._frame.append(packet)

        # return frame record
        return packet

    def close(self) -> 'None':
        """Close engine.

        This method is to be used for closing the engine instance. It is to
        close the engine instance after the extraction process is finished.

        """
        self._extmp.close()
