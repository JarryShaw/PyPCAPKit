"""A stand-in for third-party code that has never heard of :mod:`pcapkit`.

The module exists to give the :mod:`tests.utilities.test_warning_filters`
regression a *control arm*: it owns its own warning category and does not import
:mod:`pcapkit`, so anything observed about its warnings is attributable to
whatever ran in between rather than to the observation itself.

It is deliberately not named ``test_*``, so :program:`pytest` imports it only
when a test asks for it.

"""
from __future__ import annotations

import warnings


class UnrelatedWarning(UserWarning):
    """A category :mod:`pcapkit` knows nothing about."""


def emit() -> None:
    """Warn once, at the default ``stacklevel``.

    The default ``stacklevel`` of 1 is load-bearing. It makes the
    ``__warningregistry__`` consulted by the ``default`` action *this* module's,
    keyed on *this* line, so repeated calls de-duplicate however far apart their
    call sites are. Passing ``stacklevel=2`` would key the registry on each
    caller's line instead, and identical calls from two different lines would
    then both be shown -- which looks exactly like the re-firing this test is
    trying to detect.

    """
    warnings.warn('unrelated third-party complaint', UnrelatedWarning)
