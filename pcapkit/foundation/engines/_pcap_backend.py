# -*- coding: utf-8 -*-
"""Which distribution owns the :mod:`pcap` module?
=====================================================

.. module:: pcapkit.foundation.engines._pcap_backend

Two unrelated PyPI distributions install a top-level module named :mod:`pcap`:

* `PyPCAP`_ -- a Cython binding, shipped as a single extension module
  (:file:`pcap.cpython-*.so`), installable only up to Python 3.11.
* `pcap-ct`_ -- an independent :mod:`ctypes` reimplementation of the same
  interface, shipped as a *package* (:file:`pcap/__init__.py`), installable on
  3.10 and newer.

They therefore **collide**: nothing stops both from being installed, and
``import pcap`` then silently resolves to whichever the import system finds
first. Measured on Python 3.10 with both present, the ``pcap/`` package wins and
upstream's extension module is shadowed and unreachable -- so ``pcap-ct`` always
takes precedence, and no amount of ordering by the caller changes it.

:class:`~pcapkit.foundation.engines.pypcap.PyPCAP` and
:class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` are separate engines, so each
has to know which distribution it actually got rather than assume. This module is
the one place that answers that, deliberately shared: the two engines must agree
on the answer, and two copies of the detection would be two chances to disagree.
It is *only* detection -- nothing here is engine behaviour -- and it imports
nothing from :mod:`pcapkit`, so it cannot introduce an import cycle.

.. _PyPCAP: https://github.com/pynetwork/pypcap
.. _pcap-ct: https://pypi.org/project/pcap-ct/

"""
import importlib
import importlib.metadata
import sys
from typing import TYPE_CHECKING, NamedTuple

__all__ = [
    'PYPCAP', 'PCAP_CT', 'DISTRIBUTIONS', 'ENGINE_NAMES',
    'Probe', 'probe', 'identify', 'installed_distributions',
    'wrong_backend_reason', 'collision_reason',
]

if TYPE_CHECKING:
    from types import ModuleType
    from typing import Optional

#: Distribution name of upstream `PyPCAP`_.
PYPCAP = 'pypcap'
#: Distribution name of `pcap-ct`_.
PCAP_CT = 'pcap-ct'
#: Every distribution known to provide :mod:`pcap`, in a fixed order so that
#: messages naming several of them read the same way every time.
DISTRIBUTIONS = (PYPCAP, PCAP_CT)
#: The ``engine=`` string that drives each distribution. Kept here rather than in
#: either engine so that a message pointing the user at the *other* engine cannot
#: name one that does not exist.
ENGINE_NAMES = {
    PYPCAP: 'pypcap',
    PCAP_CT: 'pcap_ct',
}


class Probe(NamedTuple):
    """What one attempt to import :mod:`pcap` found."""

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
    """Which distribution does an imported :mod:`pcap` module come from?

    `pcap-ct`_ ships :mod:`pcap` as a package whose ``__init__`` does
    ``from ._pcap import *``, which binds the submodule as an attribute; upstream
    `PyPCAP`_ ships a single extension module, which has no such attribute. That
    is a structural difference rather than a cosmetic one, which is why it is
    preferred here over the alternatives:

    * ``pcap.__version__`` is ``1.3.0b3`` against ``1.3.0`` today, but that is a
      coincidence of release timing and would stop separating them the moment
      ``pcap-ct`` cuts a 1.3.0 final.
    * ``pcap.ex_name`` looked like a ``pcap-ct`` marker and is **not** -- measured
      present on upstream ``pypcap`` 1.3.0 as well.

    Args:
        module: An already-imported :mod:`pcap` module.

    Returns:
        :data:`PCAP_CT` or :data:`PYPCAP`.

    .. _PyPCAP: https://github.com/pynetwork/pypcap
    .. _pcap-ct: https://pypi.org/project/pcap-ct/

    """
    return PCAP_CT if hasattr(module, '_pcap') else PYPCAP


def installed_distributions() -> 'tuple[str, ...]':
    """Which of :data:`DISTRIBUTIONS` are installed, per package metadata.

    Asked of the metadata rather than of :mod:`pcap` itself, because that is the
    only way to see the distribution the import did *not* resolve to -- which is
    exactly the collision worth reporting.

    Returns:
        The installed subset of :data:`DISTRIBUTIONS`, in that order.

    """
    found = []  # type: list[str]
    for name in DISTRIBUTIONS:
        try:
            importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        except Exception:  # pylint: disable=broad-except
            # A corrupt or unreadable ``dist-info`` is not a reason to fail an
            # extraction. Detection is a courtesy; treat "cannot tell" as "not
            # installed" and let the import attempt be the authority.
            continue
        found.append(name)
    return tuple(found)


def _purge() -> 'None':
    """Drop the ``pcap`` and ``libpcap`` module trees from :data:`sys.modules`.

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
    well as ``pcap`` because the residue is in whichever of the two got part-way:
    purging only ``pcap`` moved the ``NameError`` from one to the other rather
    than removing it.

    """
    roots = ('pcap', 'libpcap')
    # computed once rather than per entry in sys.modules, which can be large
    prefixes = tuple(f'{root}.' for root in roots)
    for name in [name for name in sys.modules
                 if name in roots or name.startswith(prefixes)]:
        del sys.modules[name]


def probe() -> 'Probe':
    """Import :mod:`pcap` and report what was found.

    Not cached. The cost after a successful first call is a :data:`sys.modules`
    lookup, and a cache would make the answer depend on when it was first asked --
    which the tests, and anything that manipulates :data:`sys.path`, would have to
    work around. It is idempotent instead, via :func:`_purge`.

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
    """Why ``wanted`` cannot run, when some *other* distribution owns :mod:`pcap`.

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
