# -*- coding: utf-8 -*-
"""Which extraction engines can actually run on this host.

``pcapkit`` ships four extraction engines and three of them lean on something the
host may simply not have: ``dpkt``, ``scapy`` and ``pyshark`` are optional
third-party packages, and ``pyshark`` additionally drives the external ``tshark``
binary from Wireshark. On top of that, ``pyshark`` 0.6 calls
``asyncio.get_event_loop_policy().get_event_loop()`` on a thread with no running
loop. Creating one implicitly there was deprecated years ago and Python 3.14 no
longer does it, raising ``RuntimeError: There is no current event loop in thread
'MainThread'`` instead -- so on 3.14 ``pyshark`` cannot be used at all, whatever else
is installed.

None of those is a ``pcapkit`` defect, and the demos in this directory should not
die on any of them. So they call :func:`unavailable` on whatever the engine raised:
it returns a human-readable reason when the engine is merely unavailable here, and
:data:`None` when the failure is real and must be allowed to propagate.

There is a quieter failure to account for as well. When an engine's package is not
installed at all, ``Extractor`` does *not* raise -- it emits an ``EngineWarning``
and falls back to pcapkit's own parser, so the extraction succeeds and reports a
frame count that has nothing to do with the engine that was asked for.
:func:`ran_as_asked` is how the demos tell the two apart.

This module is a helper for the demos, not a demo itself.

"""

import platform
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pcapkit.foundation.extraction import Extractor

__all__ = ['ENGINES', 'unavailable', 'ran_as_asked', 'report', 'preflight']

#: The extraction engines ``pcapkit.extract(engine=...)`` accepts, in the order the
#: demos exercise them. ``'default'`` is pcapkit's own parser (also spelled
#: ``'pcapkit'``) and is the only one with no third-party requirement; further
#: engines can be added at runtime with
#: :func:`pcapkit.foundation.registry.foundation.register_extractor_engine`.
ENGINES = ('default', 'pyshark', 'scapy', 'dpkt', 'pypcap', 'pcap_ct', 'pypcapfile')

#: ``__engine_name__`` of the driver each ``engine=`` value should end up using.
#: ``'default'`` and ``'pcapkit'`` pick their parser from the file's magic number,
#: so either of two names is correct for them.
ENGINE_DRIVERS = {
    'default': ('PCAP', 'PCAP-NG'),
    'pcapkit': ('PCAP', 'PCAP-NG'),
    'dpkt': ('DPKT',),
    'scapy': ('Scapy',),
    'pyshark': ('PyShark',),
    'pypcap': ('PyPCAP',),
    'pcap_ct': ('PCAP_CT',),
    'pypcapfile': ('PyPCAPFile',),
}


def unavailable(exc: 'Exception') -> 'str | None':
    """Explain *exc* if it means the engine cannot run on this host.

    Args:
        exc: Exception the engine raised.

    Returns:
        A reason to report the engine as skipped, or :data:`None` if *exc* is a
        genuine failure that the caller should re-raise.

    """
    # A missing optional package. pcapkit raises its own ModuleNotFound, which
    # derives from ImportError, so one check covers both it and a plain import.
    if isinstance(exc, ImportError):
        return f'{exc.name or exc} is not installed'

    # pyshark needs Wireshark's tshark on PATH. Matched by name rather than
    # imported, since pyshark itself may be the thing that is missing.
    if type(exc).__name__ == 'TSharkNotFoundException':
        return 'the tshark binary from Wireshark is not installed'

    # pyshark 0.6 on Python 3.14: it asks the event loop policy for the current
    # loop on a thread that has none. Not something pcapkit can work around.
    if isinstance(exc, RuntimeError) and 'event loop' in str(exc):
        version = '.'.join(str(part) for part in sys.version_info[:3])
        return (f'{exc} -- pyshark asks for an implicit asyncio event loop, '
                f'which Python {version} no longer provides (pyshark bug, not pcapkit)')

    # The prerelease pcap-ct/libpcap wheels are platform-neutral, but their
    # bundled configuration currently asks macOS to load Linux's libc.so.6.
    # That makes the optional engine unavailable on this host, not a failure in
    # the extraction being benchmarked.
    if isinstance(exc, OSError) and 'libc.so.6' in str(exc):
        return (f'pcap-ct/libpcap cannot load its Linux libc.so.6 dependency on '
                f'{platform.system()}')

    return None


def ran_as_asked(engine: 'str', extraction: 'Extractor') -> 'tuple[str, bool]':
    """Which driver *extraction* really used, and whether it is the one asked for.

    Args:
        engine: Engine name that was passed to ``pcapkit.extract``.
        extraction: The resulting extractor.

    Returns:
        The driver's ``__engine_name__`` and whether it matches *engine*. A
        mismatch means the engine's package is not installed and ``Extractor``
        fell back to its own parser, having only warned about it.

    """
    driver = extraction.engine.__engine_name__
    return driver, driver in ENGINE_DRIVERS.get(engine, (engine,))


def _declared_reason(engine: 'str') -> 'str | None':
    """What the engine itself says about running here, if it says anything.

    Looks the engine class up in ``Extractor.__engine__`` and asks its
    ``unsupported_reason()``. Returns :data:`None` for ``'default'``, for an engine
    name the registry does not know, or for anything that goes wrong on the way --
    this is a nicety for the demos' skip messages, and must never be the reason one
    of them fails.

    Args:
        engine: Engine name, as passed to ``pcapkit.extract``.

    Returns:
        The engine's own reason, or :data:`None`.

    """
    try:
        from pcapkit.foundation.extraction import Extractor

        registered = Extractor.__engine__.get(engine)
        if registered is None:
            return None
        klass = getattr(registered, 'klass', registered)
        return klass.unsupported_reason()
    except Exception:  # pylint: disable=broad-except
        return None


def report(engine: 'str', detail: 'str') -> 'None':
    """Print one line of an engine report.

    Args:
        engine: Engine name.
        detail: What happened, e.g. ``'6 frames'`` or ``'skipped -- ...'``.

    """
    print(f'{engine:>8}: {detail}', flush=True)


def preflight(engine: 'str', fin: 'str') -> 'str | None':
    """Try *engine* once on *fin* and report whether it works here.

    Useful before a timing or benchmarking run, where the extraction itself is
    repeated thousands of times and a failure on the first round would throw the
    whole measurement away.

    Args:
        engine: Engine name to try.
        fin: Capture file to read.

    Returns:
        :data:`None` if the engine works, else the reason it is unavailable.

    Raises:
        Exception: Whatever the engine raised, if it is a real failure rather than
            the engine being unavailable on this host.

    """
    import pcapkit  # imported here so this module stays importable on its own

    # Ask the engine first. ``unsupported_reason`` is the same preflight check
    # ``Extractor.run`` consults, and it names the actual cause -- a Python
    # ceiling, a missing tshark, a missing libpcap, the wrong ``pcap``
    # distribution. Without it the fallback branch below is all that fires, and it
    # can only guess "its package is not installed", which is wrong whenever the
    # package is installed and unusable.
    reason = _declared_reason(engine)
    if reason is not None:
        return reason

    try:
        extraction = pcapkit.extract(fin=fin, store=False, nofile=True, verbose=False,
                                     engine=engine)  # type: ignore[arg-type]
    except Exception as exc:  # pylint: disable=broad-except
        reason = unavailable(exc)
        if reason is None:
            raise
        return reason

    driver, asked = ran_as_asked(engine, extraction)
    if not asked:
        return (f'its package is not installed -- pcapkit fell back to its own '
                f'{driver} parser, so timing it would measure the wrong thing')
    return None
