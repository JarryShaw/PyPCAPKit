# -*- coding: utf-8 -*-
"""Extraction Options
========================

.. module:: pcapkit.foundation.options

:mod:`pcapkit.foundation.options` contains the options classes an
:class:`~pcapkit.foundation.extraction.Extractor` takes: one per feature, each
an immutable :class:`~pcapkit.corekit.infoclass.Info` built from keywords alone.

"""
import io
import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.exceptions import RegistryError

if TYPE_CHECKING:
    from typing import Iterable, Optional

    from typing_extensions import Literal

    from pcapkit.foundation.extraction import Formats

__all__ = ['DumpOptions', 'ReassemblyOptions', 'TraceFlowOptions', 'StreamOptions']


def _names(kind: 'str', protocols: 'Iterable[str]') -> 'tuple[str, ...]':
    """Read ``protocols`` as the names an options class enables.

    Arguments:
        kind: the options class, for the error message
        protocols: the names given

    Returns:
        The names, lower-cased, each once, in the order given.

    Raises:
        RegistryError: If ``protocols`` is not a list of names.

    """
    # NOTE: a string is iterable, so it is refused by name rather than read as its letters.
    try:
        names = None if isinstance(protocols, (str, bytes)) else tuple(protocols)
    except TypeError:
        names = None
    if names is None or not all(isinstance(name, str) for name in names):
        raise RegistryError(f'{kind}: protocols must be a list of registered names, not {protocols!r}')
    return tuple(dict.fromkeys(name.lower() for name in names))


@info_final
class DumpOptions(Info):
    """Output settings of an :class:`~pcapkit.foundation.extraction.Extractor`.

    Args:
        fout: output file name, or under ``files`` the directory the files
            go in
        format: output file format, a key of :attr:`Extractor.__output__
            <pcapkit.foundation.extraction.Extractor.__output__>`
        files: whether each frame is dumped to a file of its own
        extension: whether the format's file extension is appended to
            ``fout`` when it lacks one; not under ``files``

    Raises:
        RegistryError: If ``fout`` is not a :obj:`str`.

    .. versionadded:: 1.7.0

    """

    #: Output file name, or the directory under ``files``.
    fout: 'str'
    #: Output file format.
    format: 'Formats'
    #: Whether each frame is dumped to a file of its own.
    files: 'bool'
    #: Whether the format's file extension is appended to ``fout``.
    extension: 'bool'

    def __init__(self, *, fout: 'str', format: 'Formats' = 'tree',  # pylint: disable=super-init-not-called,redefined-builtin
                 files: 'bool' = False, extension: 'bool' = True) -> 'None':
        if not isinstance(fout, str):
            raise RegistryError(f'DumpOptions: fout must be a file name, not {fout!r}')
        self.__update__(fout=fout, format=format, files=files, extension=extension)
        self.__post_init__()


@info_final
class ReassemblyOptions(Info):
    """Reassembly settings of an :class:`~pcapkit.foundation.extraction.Extractor`.

    Args:
        protocols: names of the reassemblers to enable, as registered in
            :attr:`Extractor.__reassembly__
            <pcapkit.foundation.extraction.Extractor.__reassembly__>`, matched
            lower-cased
        strict: whether a datagram not completely reassembled is reported as
            the tuple of its received runs, rather than as one contiguous
            payload
        store: whether reassembled datagrams are stored
        timeout: reassembly timeout in seconds, on the *capture's* own clock;
            :data:`None` selects each protocol's own default -- 60 seconds for
            IPv4 (:rfc:`1122#section-3.3.2`) and IPv6 (:rfc:`8200#section-4.5`),
            disabled for TCP, DTLS, SCTP and TLS, which no specification gives a
            deadline (:rfc:`6347#section-4.2.3`, :rfc:`9260#section-6.9`). Pass
            :data:`math.inf` to disable it everywhere

    An :class:`~pcapkit.foundation.extraction.Extractor` given no names turns
    the feature off, as :data:`None` does, and warns that it does.

    Raises:
        RegistryError: If ``protocols`` is not a list of names.

    .. versionadded:: 1.7.0

    """

    #: Names of the reassemblers to enable, lower-cased, each once.
    protocols: 'tuple[str, ...]'
    #: Whether an incomplete datagram is reported as its received runs.
    strict: 'bool'
    #: Whether reassembled datagrams are stored.
    store: 'bool'
    #: Reassembly timeout in seconds, or :data:`None` for each protocol's own.
    timeout: 'Optional[float]'

    def __init__(self, *, protocols: 'Iterable[str]', strict: 'bool' = True,  # pylint: disable=super-init-not-called
                 store: 'bool' = True, timeout: 'Optional[float]' = None) -> 'None':
        self.__update__(protocols=_names('ReassemblyOptions', protocols),
                        strict=strict, store=store, timeout=timeout)
        self.__post_init__()


@info_final
class TraceFlowOptions(Info):
    """Flow tracing settings of an :class:`~pcapkit.foundation.extraction.Extractor`.

    Args:
        protocols: names of the flow tracers to enable, as registered in
            :attr:`Extractor.__traceflow__
            <pcapkit.foundation.extraction.Extractor.__traceflow__>`, matched
            lower-cased
        fout: output root path
        format: output file format
        byteorder: output file byte order
        nanosecond: output nanosecond-resolution file flag
        bidirectional: whether both halves of a conversation are traced as one
            flow; :data:`False` traces a flow per direction
        analyze: whether each traced flow reassembles its application layer,
            so that its ``packet`` can be read. Off by default, because it
            buffers every traced payload -- a cost tracing does not otherwise
            pay. Unavailable on the ``pyshark`` engine, which reports dissected
            fields rather than the octets behind them
        timeout: idle timeout in seconds, measured on the capture's own clock:
            a flow none of whose packets is more recent is finalised, as
            :meth:`TraceFlow.advance
            <pcapkit.foundation.traceflow.traceflow.TraceFlow.advance>` does;
            :data:`None` keeps every flow until the end of the capture

    An :class:`~pcapkit.foundation.extraction.Extractor` given no names turns
    the feature off, as :data:`None` does, and warns that it does.

    Raises:
        RegistryError: If ``protocols`` is not a list of names.

    .. versionadded:: 1.7.0

    .. versionchanged:: 1.10.0

       Takes ``timeout`` (:issue:`2956`).

    """

    #: Names of the flow tracers to enable, lower-cased, each once.
    protocols: 'tuple[str, ...]'
    #: Output root path.
    fout: 'str'
    #: Output file format.
    format: 'str'
    #: Output file byte order.
    byteorder: 'Literal["big", "little"]'
    #: Output nanosecond-resolution file flag.
    nanosecond: 'bool'
    #: Whether both halves of a conversation are one flow.
    bidirectional: 'bool'
    #: Whether each traced flow reassembles its application layer.
    analyze: 'bool'
    #: Idle timeout in seconds, on the capture's clock, or :data:`None`.
    #:
    #: .. versionadded:: 1.10.0
    timeout: 'Optional[float]'

    def __init__(self, *, protocols: 'Iterable[str]', fout: 'str' = './tmp',  # pylint: disable=super-init-not-called
                 format: 'str' = 'pcap',  # pylint: disable=redefined-builtin
                 byteorder: 'Literal["big", "little"]' = sys.byteorder, nanosecond: 'bool' = False,
                 bidirectional: 'bool' = True, analyze: 'bool' = False,
                 timeout: 'Optional[float]' = None) -> 'None':
        self.__update__(protocols=_names('TraceFlowOptions', protocols), fout=fout,
                        format=format, byteorder=byteorder, nanosecond=nanosecond,
                        bidirectional=bidirectional, analyze=analyze, timeout=timeout)
        self.__post_init__()


@info_final
class StreamOptions(Info):
    """Input stream settings of an :class:`~pcapkit.foundation.extraction.Extractor`.

    The buffer settings apply to an input that cannot seek, such as a pipe,
    which is read through a :class:`~pcapkit.corekit.io.SeekableReader`.

    Args:
        buffer_size: buffer size for reading the input
        buffer_save: whether the buffered input is saved to a file
        buffer_path: path of that file; :data:`None` uses a temporary file,
            deleted when the input is closed
        no_eof: whether to not raise :exc:`EOFError` at the end of the input
            but retry instead, which is what a live capture on a pipe or on
            standard input wants, since a read there blocks until the writer
            produces more or closes. Retrying stops as soon as one retry finds
            nothing new, so an exhausted input finishes rather than spinning;
            on a *seekable* input, where nothing blocks, that means a file still
            being appended to ends at the data present when the extraction
            reached it

    .. versionadded:: 1.7.0

    """

    #: Buffer size for reading the input.
    buffer_size: 'int'
    #: Whether the buffered input is saved to a file.
    buffer_save: 'bool'
    #: Path of that file, or :data:`None` for a temporary one.
    buffer_path: 'Optional[str]'
    #: Whether reaching the end of the input retries rather than stops.
    no_eof: 'bool'

    def __init__(self, *, buffer_size: 'int' = io.DEFAULT_BUFFER_SIZE,  # pylint: disable=super-init-not-called
                 buffer_save: 'bool' = False, buffer_path: 'Optional[str]' = None,
                 no_eof: 'bool' = False) -> 'None':
        self.__update__(buffer_size=buffer_size, buffer_save=buffer_save,
                        buffer_path=buffer_path, no_eof=no_eof)
        self.__post_init__()
