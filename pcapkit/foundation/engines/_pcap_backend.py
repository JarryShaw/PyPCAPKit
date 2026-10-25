# -*- coding: utf-8 -*-
"""Which distribution owns the |pcap|_ module?
=====================================================

.. module:: pcapkit.foundation.engines._pcap_backend

Unrelated PyPI distributions install a top-level module named |pcap|_:

* `PyPCAP`_ -- a Cython binding, shipped as a single extension module
  (:file:`pcap.cpython-*.so`), installable only up to Python 3.11.
* `pcap-ct`_ -- an independent :mod:`ctypes` reimplementation of the same
  interface, shipped as a *package* (:file:`pcap/__init__.py`), installable on
  3.10 and newer.

They therefore **collide**: nothing stops more than one from being installed, and
``import pcap`` then silently resolves to whichever the import system finds
first. Measured on Python 3.10 with both present, the ``pcap/`` package wins and
upstream's extension module is shadowed and unreachable -- so ``pcap-ct`` always
takes precedence, and no amount of ordering by the caller changes it.

:class:`~pcapkit.foundation.engines.pypcap.PyPCAP` and
:class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` are separate engines, so each
has to know which distribution it actually got rather than assume. This module is
the one place that answers that, deliberately shared: the engines must agree on
the answer, and a copy of the detection in each would be a chance to disagree.
It is *only* detection -- nothing here is engine behaviour -- and it imports
nothing from :mod:`pcapkit` but :mod:`pcapkit.corekit.infoclass`, which imports
nothing from :mod:`pcapkit.foundation`, so it cannot introduce an import cycle.

"""
import contextvars
import importlib
import importlib.metadata
import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

__all__ = [
    'PYPCAP', 'PCAP_CT', 'DISTRIBUTIONS', 'ENGINE_NAMES',
    'Probe', 'Memo', 'probe', 'identify', 'installed_distributions',
    'wrong_backend_reason', 'engine_reason', 'collision_reason',
]

if TYPE_CHECKING:
    from types import ModuleType
    from typing import Optional

#: Distribution name of upstream `PyPCAP`_.
PYPCAP = 'pypcap'
#: Distribution name of `pcap-ct`_.
PCAP_CT = 'pcap-ct'
#: Every distribution known to provide |pcap|_, in a fixed order so that
#: messages naming several of them read the same way every time.
DISTRIBUTIONS = (PYPCAP, PCAP_CT)
#: The ``engine=`` string that drives each distribution. Kept here rather than in
#: either engine so that a message pointing the user at the *other* engine cannot
#: name one that does not exist.
ENGINE_NAMES = {
    PYPCAP: 'pypcap',
    PCAP_CT: 'pcap_ct',
}


@info_final
class Probe(Info):
    """What one attempt to import |pcap|_ found."""

    #: Distribution that provided the imported module -- :data:`PYPCAP`,
    #: :data:`PCAP_CT`, or :data:`None` when the import did not succeed.
    name: 'Optional[str]'
    #: ``pcap.__version__``, when there was a module to read it from.
    version: 'Optional[str]'
    #: ``pcap.__file__``, which is what distinguishes an extension module from a
    #: package directory to a human reading a bug report.
    origin: 'Optional[str]'
    #: Why the import failed, as a short phrase, or :data:`None` on success.
    failure: 'Optional[str]'
    #: Whether the failure was simply "not installed", i.e. an
    #: :exc:`ImportError`. This matters because
    #: :meth:`Extractor.import_test
    #: <pcapkit.foundation.extraction.Extractor.import_test>` already reports that
    #: case perfectly well, whereas the *other* kind of failure escapes it --
    #: see :func:`probe`.
    missing: 'bool'
    #: Distributions found installed, whether or not their module was importable.
    #: More than one means the collision described in this module's docstring.
    installed: 'tuple[str, ...]'

    def describe(self) -> 'str':
        """A one-line description fit for a warning or a bug report.

        Returns:
            Something like ``pcap-ct 1.3.0b3 (/.../pcap/__init__.py)``, or a
            phrase naming the failure when there is no module to describe.

        """
        if self.name is None:
            return f'no usable `pcap` module ({self.failure})'
        version = self.version or 'unknown version'
        origin = self.origin or 'unknown location'
        return f'{self.name} {version} ({origin})'


def identify(module: 'ModuleType') -> 'str':
    """Which distribution does an imported |pcap|_ module come from?

    `pcap-ct`_ ships |pcap|_ as a package whose ``__init__`` does
    ``from ._pcap import *``, which binds the submodule as an attribute; upstream
    `PyPCAP`_ ships a single extension module, which has no such attribute. That
    is a structural difference rather than a cosmetic one, which is why it is
    preferred here over the alternatives:

    * ``pcap.__version__`` is ``1.3.0b3`` against ``1.3.0`` upstream, but that is a
      coincidence of release timing and would stop separating them the moment
      ``pcap-ct`` cuts a 1.3.0 final.
    * ``pcap.ex_name`` looked like a ``pcap-ct`` marker and is **not** -- measured
      present on upstream ``pypcap`` 1.3.0 as well.

    Args:
        module: An already-imported |pcap|_ module.

    Returns:
        :data:`PCAP_CT` or :data:`PYPCAP`.

    """
    return PCAP_CT if hasattr(module, '_pcap') else PYPCAP


def installed_distributions() -> 'tuple[str, ...]':
    """Which of :data:`DISTRIBUTIONS` are installed, per package metadata.

    Asked of the metadata rather than of |pcap|_ itself, because that is the
    only way to see the distribution the import did *not* resolve to -- which is
    exactly the collision worth reporting.

    Only the existence of a ``dist-info`` is asked about, through
    :func:`importlib.metadata.distributions` rather than
    :func:`importlib.metadata.distribution`. From Python 3.15 the latter parses
    every candidate's ``METADATA`` file to prefer one that has metadata, and since
    this runs on every ``pcap_ct`` extraction, that parse made the engine about
    2.3x slower per packet (:issue:`2110`). Either call finds a distribution
    exactly when the other does.

    Returns:
        The installed subset of :data:`DISTRIBUTIONS`, in that order.

    """
    found = []  # type: list[str]
    for name in DISTRIBUTIONS:
        try:
            if next(iter(importlib.metadata.distributions(name=name)), None) is None:
                continue
        except Exception:  # pylint: disable=broad-except  # nosec: B112  # see below
            # A corrupt or unreadable ``dist-info`` is not a reason to fail an
            # extraction. Detection is a courtesy; treat "cannot tell" as "not
            # installed" and let the import attempt be the authority.
            continue
        found.append(name)
    return tuple(found)


def _purge() -> 'None':
    """Drop the |pcap|_ and ``libpcap`` module trees from :data:`sys.modules`.

    Called after a failed import so that the *next* probe reproduces the same
    failure. Without it a second attempt reports something else entirely, which
    was measured rather than imagined.

    Both ``pcap-ct``'s and ``libpcap``'s package initialisers open with
    ``from .__about__ import * ; del __about__``, which is **not safe to re-run**:
    the ``del`` needs a name that only gets bound as a side effect of importing
    the submodule fresh. When the initialiser fails part-way -- as it does with no
    system :manpage:`libpcap(3)`, where the real error is
    ``OSError: Cannot find libpcap.so library`` -- Python removes the package it
    was executing but leaves the ``__about__`` submodule cached, so the retry
    reaches the ``del`` with nothing bound and dies with
    ``NameError: name '__about__' is not defined``.

    That message names neither the missing library nor the package it came from,
    and it is what the user would otherwise be shown. ``libpcap`` is purged as
    well as |pcap|_ because the residue is in whichever of the two got part-way:
    purging only |pcap|_ moved the ``NameError`` from one to the other rather
    than removing it.

    """
    roots = ('pcap', 'libpcap')
    # computed once rather than per entry in sys.modules, which can be large
    prefixes = tuple(f'{root}.' for root in roots)
    for name in [name for name in sys.modules
                 if name in roots or name.startswith(prefixes)]:
        del sys.modules[name]


class Memo:
    """One extraction's :func:`probe`, taken at most once (:issue:`2113`).

    Engine selection asks
    :meth:`~pcapkit.foundation.engines.engine.EngineBase.unsupported_reason` in
    the :class:`~pcapkit.foundation.extraction.Extractor` constructor and again in
    :meth:`~pcapkit.foundation.extraction.Extractor.run`, and the engine's own
    constructor probes once more. While a memo is entered, :func:`probe` answers
    from it, probing on first use. Each extraction holds its own memo, so nothing
    is cached across extractions.

    """

    __slots__ = ('found', '_tokens')

    def __init__(self) -> 'None':
        #: The probe taken under this memo, or :data:`None` before the first.
        self.found = None  # type: Optional[Probe]
        self._tokens = []  # type: list[contextvars.Token[Optional[Memo]]]

    def __enter__(self) -> 'Memo':
        self._tokens.append(_MEMO.set(self))
        return self

    def __exit__(self, *exc: 'object') -> 'None':
        _MEMO.reset(self._tokens.pop())


#: The :class:`Memo` entered in this context, if any. A
#: :class:`~contextvars.ContextVar` so that one thread's extraction never answers
#: another's.
_MEMO: 'contextvars.ContextVar[Optional[Memo]]' = contextvars.ContextVar('_MEMO', default=None)


def probe() -> 'Probe':
    """Import |pcap|_ and report what was found.

    Not cached, except within a :class:`Memo`, which an extraction enters so
    that its engine selection and engine constructor share one probe
    (:issue:`2113`). The cost after a successful first call is a
    :data:`sys.modules` lookup plus the ``dist-info`` scan in
    :func:`installed_distributions`, and a process-wide cache would make the
    answer depend on when it was first asked -- which the tests, and anything that
    manipulates :data:`sys.path`, would have to work around. It is idempotent
    instead, via :func:`_purge`.

    Note:
        The bare ``except Exception`` is deliberate and is much of the point of
        this function. ``pcap-ct`` imports the ``libpcap`` distribution, whose
        Linux loader calls :func:`ctypes.util.find_library` and raises
        :exc:`OSError` -- ``Cannot find libpcap.so library`` -- when no system
        :manpage:`libpcap(3)` is present. :exc:`OSError` is not an
        :exc:`ImportError`, so :meth:`Extractor.import_test
        <pcapkit.foundation.extraction.Extractor.import_test>` does not catch it
        and it escapes as a hard error instead of degrading to the default engine.
        Catching it here is what lets an engine report it as a reason instead.

    Returns:
        A :class:`Probe` describing the outcome.

    """
    memo = _MEMO.get()
    if memo is None:
        return _probe()
    if memo.found is None:
        memo.found = _probe()
    return memo.found


def _probe() -> 'Probe':
    """:func:`probe`, without consulting a :class:`Memo`."""
    installed = installed_distributions()

    try:
        module = importlib.import_module('pcap')
    except ImportError as exc:
        _purge()
        return Probe(None, None, None, str(exc) or 'no module named `pcap`', True, installed)
    except Exception as exc:  # pylint: disable=broad-except
        _purge()
        return Probe(None, None, None, f'{type(exc).__name__}: {exc}', False, installed)

    return Probe(
        identify(module),
        getattr(module, '__version__', None),
        getattr(module, '__file__', None),
        None,
        False,
        installed,
    )


def wrong_backend_reason(wanted: 'str', found: 'Probe') -> 'Optional[str]':
    """Why ``wanted`` cannot run, when some *other* distribution owns |pcap|_.

    Args:
        wanted: The distribution the calling engine drives -- :data:`PYPCAP` or
            :data:`PCAP_CT`.
        found: The result of :func:`probe`.

    Returns:
        A reason naming what was found and which ``engine=`` string wants it, or
        :data:`None` when ``wanted`` is what is installed, or when nothing is --
        an absent module is not this function's business, since
        :meth:`Extractor.import_test
        <pcapkit.foundation.extraction.Extractor.import_test>` reports that.

    """
    if found.name is None or found.name == wanted:
        return None

    alternative = ENGINE_NAMES.get(found.name)
    suggestion = f"; use 'engine={alternative}' for it" if alternative else ''
    return (f'the installed `pcap` module is {found.name} '
            f'({found.version or "unknown version"}), not {wanted}{suggestion}')


def engine_reason(wanted: 'str', found: 'Probe') -> 'Optional[str]':
    """Why the engine driving ``wanted`` cannot run on ``found``, if it cannot.

    The verdict both engines' ``unsupported_reason()`` give, kept in one place so
    that they agree (:issue:`2132`).

    Args:
        wanted: The distribution the calling engine drives -- :data:`PYPCAP` or
            :data:`PCAP_CT`.
        found: The result of :func:`probe`.

    Returns:
        :func:`wrong_backend_reason`'s answer when another distribution owns
        |pcap|_; a phrase carrying the import failure when |pcap|_ is installed
        but raised something other than :exc:`ImportError` -- ``OSError: Cannot
        find libpcap.so library`` with no system :manpage:`libpcap(3)`, say; and
        :data:`None` otherwise. An absent module is still :data:`None`, since
        :meth:`Extractor.import_test
        <pcapkit.foundation.extraction.Extractor.import_test>` reports that.

    """
    wrong = wrong_backend_reason(wanted, found)
    if wrong is not None:
        return wrong

    # ``missing`` separates "not installed", which the import test reports
    # well, from a failure that would otherwise escape it -- the missing
    # ``libpcap.so`` being the case this exists for.
    if found.name is None and not found.missing:
        return f'the `pcap` module is installed but unusable -- {found.failure}'

    return None


def collision_reason(found: 'Probe') -> 'Optional[str]':
    """A description of both distributions being installed at once, if they are.

    Returns:
        A phrase naming every installed distribution and which one ``import pcap``
        actually resolved to, or :data:`None` when at most one is installed.

    """
    if len(found.installed) < 2:
        return None

    names = ' and '.join(found.installed)
    return (f'{names} are installed together, and both provide the `pcap` module; '
            f'`import pcap` resolved to {found.describe()}, leaving the other '
            f'shadowed and unreachable -- install exactly one of them so the '
            f'choice is explicit')
