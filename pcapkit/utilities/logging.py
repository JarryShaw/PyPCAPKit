# -*- coding: utf-8 -*-
"""Logging System
====================

.. module:: pcapkit.utilities.logging

:mod:`pcapkit.utilities.logging` integrates :mod:`pcapkit` with the standard
:mod:`logging` system. It owns the package-wide logger hierarchy rooted at
:data:`~pcapkit.utilities.logging.logger` (the logger named ``pcapkit``), and
the :func:`~pcapkit.utilities.logging.configure` and
:func:`~pcapkit.utilities.logging.reset` pair through which an application
decides what, if anything, :mod:`pcapkit` emits.

:mod:`pcapkit` is a library, so importing it configures **no** logging output:
the only handler attached to :data:`logger` is a :class:`logging.NullHandler`,
and no level is set, which leaves both the destination and the verbosity to the
embedding application. Every module logs through its own child logger, obtained
via :func:`get_logger` with ``__name__``, so that a single subtree may be
silenced or amplified independently::

   import logging
   logging.getLogger('pcapkit.foundation.registry').setLevel(logging.WARNING)

For applications that do not configure :mod:`logging` themselves,
:func:`configure` attaches a handler of :mod:`pcapkit`'s own::

   import sys
   from pcapkit.utilities.logging import configure
   configure('DEBUG', stream=sys.stderr)

and :func:`reset` puts everything back the way importing :mod:`pcapkit` left it.

.. seealso::

   :envvar:`PCAPKIT_DEVMODE` still bootstraps the historical :obj:`sys.stderr`
   handler at :data:`logging.DEBUG`, so a development session needs no explicit
   :func:`configure` call.

"""
import logging
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import IO, Optional, Union

__all__ = [
    'logger', 'get_logger', 'configure', 'reset', 'ensure_output',
    'ROOT_LOGGER_NAME', 'DEFAULT_FORMAT', 'DEFAULT_DATE_FORMAT',
]

###############################################################################
# Dev Mode
###############################################################################

# boolean mappings
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}

#: bool: Development mode flag.
DEVMODE = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_DEVMODE', 'false').casefold(), False)
#: bool: Verbose output flag.
VERBOSE = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_VERBOSE', 'false').casefold(), False)

###############################################################################
# Sphinx Mode
###############################################################################

#: bool: This is a workaround for :data:`typing.TYPE_CHECKING` in Sphinx.
SPHINX_TYPE_CHECKING = BOOLEAN_STATES.get(os.environ.get('PCAPKIT_SPHINX', 'false').casefold(), False)

###############################################################################
# Logger Setup
###############################################################################

#: str: Name of the logger at the root of :mod:`pcapkit`'s hierarchy.
ROOT_LOGGER_NAME = 'pcapkit'

#: str: Default :class:`logging.Formatter` format string.
DEFAULT_FORMAT = '[%(levelname)s] %(asctime)s - %(message)s'
#: str: Default :class:`logging.Formatter` date format string.
DEFAULT_DATE_FORMAT = '%m/%d/%Y %I:%M:%S %p'

#: logging.Logger: :class:`~logging.Logger` instance named after ``pcapkit``,
#: at the root of the package's logger hierarchy. Per-module loggers are its
#: children, so configuring this one configures all of :mod:`pcapkit`.
logger = logging.getLogger(ROOT_LOGGER_NAME)

#: logging.Formatter: Default formatter, used by any handler that
#: :func:`configure` creates and by the :envvar:`PCAPKIT_DEVMODE` bootstrap.
formatter = logging.Formatter(fmt=DEFAULT_FORMAT, datefmt=DEFAULT_DATE_FORMAT)

#: logging.StreamHandler: The historical :obj:`sys.stderr` handler. It is only
#: *attached* under :envvar:`PCAPKIT_DEVMODE`; it is constructed unconditionally
#: so that ``logger.addHandler(handler)`` remains a one-line way back to the
#: pre-1.4 default output.
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(formatter)


def get_logger(name: 'Optional[str]' = None) -> 'logging.Logger':
    """Retrieve a logger inside :mod:`pcapkit`'s hierarchy.

    This is the accessor every module in :mod:`pcapkit` uses, as
    ``logger = get_logger(__name__)``, so that records carry the emitting
    module's name and an application can address one subtree at a time.

    Args:
        name: Dotted logger name, normally the caller's :data:`__name__`.
            :data:`None` or ``'pcapkit'`` yields the root :data:`logger`.
            A name outside the ``pcapkit`` hierarchy -- notably ``'__main__'``,
            which is what :data:`__name__` reports for a module run as a
            script -- is placed *under* the root rather than beside it, since a
            sibling of ``pcapkit`` would escape every :mod:`pcapkit`-level
            configuration.

    Returns:
        The requested logger.

    """
    if not name or name == ROOT_LOGGER_NAME:
        return logger
    if name.startswith(f'{ROOT_LOGGER_NAME}.'):
        return logging.getLogger(name)
    return logger.getChild(name)


def _detach(target: 'logging.Logger') -> 'None':
    """Remove every handler attached to ``target``.

    Handlers are detached but deliberately never closed: a handler reached here
    was either built from a stream the caller still owns, or handed to
    :func:`configure` ready-made, and closing someone else's file or socket on
    their behalf is not this module's business. Whoever created a handler closes
    it.

    Args:
        target: Logger to strip.

    """
    for entry in list(target.handlers):
        target.removeHandler(entry)


def _has_output(target: 'logging.Logger') -> 'bool':
    """Whether a record from ``target`` would reach a real handler.

    Walks the ancestry the way :meth:`logging.Logger.callHandlers` does,
    stopping where propagation stops, and ignores
    :class:`~logging.NullHandler` since its whole purpose is to swallow records.

    Args:
        target: Logger to inspect.

    Returns:
        :data:`True` if some handler would receive the record.

    """
    current = target  # type: Optional[logging.Logger]
    while current is not None:
        for entry in current.handlers:
            if not isinstance(entry, logging.NullHandler):
                return True
        if not current.propagate:
            break
        current = current.parent
    return False


def ensure_output(level: 'Union[int, str]' = logging.DEBUG, *,
                  stream: 'Optional[IO[str]]' = None) -> 'bool':
    """Guarantee that :mod:`pcapkit`'s records have somewhere to go.

    This is for a caller that has switched something on precisely *because* it
    wants to see the output, and for which staying silent merely because the
    application never configured :mod:`logging` would be unhelpful.

    Note that ``Extractor(verbose=True)`` and the CLI's ``-v`` do **not** go
    through here: their frame chains are user-facing output and are written to
    :data:`sys.stdout` with :func:`print`, so they are visible with no logging
    configuration at all. Nothing in :mod:`pcapkit` calls this function itself;
    it exists for consumers.

    An application that has configured its own handlers has already answered the
    question, so nothing is changed in that case.

    Args:
        level: Level to configure if, and only if, a handler has to be added.
        stream: Where to write, defaulting to :obj:`sys.stderr`.

    Returns:
        :data:`True` if a handler was added, :data:`False` if output was already
        going somewhere and the existing configuration was left alone.

    """
    if _has_output(logger):
        return False
    configure(level, stream=stream or sys.stderr, replace=False)
    return True


def reset(name: 'Optional[str]' = None) -> 'logging.Logger':
    """Restore a :mod:`pcapkit` logger to its pristine, library-neutral state.

    That is: no handlers other than the :class:`logging.NullHandler` on the
    root, no level of its own (:data:`logging.NOTSET`, so the level is inherited
    from the application's configuration), and propagation enabled.

    Args:
        name: Logger to reset, as accepted by :func:`get_logger`. Defaults to
            the root :data:`logger`, which also resets nothing else -- children
            keep any level explicitly set on them.

    Returns:
        The logger that was reset.

    Note:
        This discards the :envvar:`PCAPKIT_DEVMODE` bootstrap along with
        everything else. To reinstate it, call
        ``configure(logging.DEBUG, stream=sys.stderr)``.

    """
    target = get_logger(name)

    _detach(target)
    target.setLevel(logging.NOTSET)
    target.propagate = True

    if target is logger:
        # the null handler is what keeps a library quiet rather than noisy:
        # without it, ``logging`` prints its own "no handlers could be found"
        # complaint the first time an unconfigured application triggers a record
        target.addHandler(logging.NullHandler())
    return target


def configure(level: 'Optional[Union[int, str]]' = None, *,
              name: 'Optional[str]' = None,
              stream: 'Optional[IO[str]]' = None,
              handler: 'Optional[logging.Handler]' = None,  # pylint: disable=redefined-outer-name
              fmt: 'Optional[str]' = None,
              datefmt: 'Optional[str]' = None,
              propagate: 'Optional[bool]' = None,
              replace: 'bool' = True) -> 'logging.Logger':
    """Configure :mod:`pcapkit`'s logging at runtime.

    Every argument is optional and only the ones supplied take effect, so this
    is usable both as a one-shot setup call and as a targeted adjustment.

    Args:
        level: Level for the logger, as either a :obj:`str` name (``'DEBUG'``)
            or an :obj:`int` (:data:`logging.DEBUG`). Left untouched when
            :data:`None`, which for a freshly imported :mod:`pcapkit` means the
            level is inherited from the application.
        name: Logger to configure, as accepted by :func:`get_logger`. Defaults
            to the root :data:`logger`; pass e.g.
            ``'pcapkit.foundation.registry'`` to configure one subtree.
        stream: Writable text stream to log to, e.g. :obj:`sys.stderr`. A
            :class:`logging.StreamHandler` is created for it and given a
            :class:`logging.Formatter` built from ``fmt`` and ``datefmt``.
        handler: An already-built handler to attach instead, for anything a
            plain stream cannot express -- a
            :class:`~logging.handlers.RotatingFileHandler`, a queue handler, a
            test double. Mutually exclusive with ``stream``. Its formatter is
            only replaced if ``fmt`` or ``datefmt`` is given.
        fmt: Format string for the handler this call creates. Defaults to
            :data:`DEFAULT_FORMAT`.
        datefmt: Date format string for the handler this call creates. Defaults
            to :data:`DEFAULT_DATE_FORMAT`.
        propagate: Whether records should reach ancestor loggers. Setting this
            to :data:`False` on the root :data:`logger` keeps :mod:`pcapkit`'s
            records out of the application's own handlers.
        replace: Whether to detach the logger's existing handlers first, so that
            repeated calls replace rather than accumulate output. Pass
            :data:`False` to add a second destination. Unlike :func:`reset`,
            this only touches handlers -- the level and propagation are left
            alone unless the corresponding arguments are given.

    Returns:
        The logger that was configured, for chaining or inspection.

    Raises:
        ValueError: If both ``stream`` and ``handler`` are given, since which
            one is meant to receive ``fmt`` would be ambiguous.

    Example:
        Restore the pre-1.4 default of :obj:`sys.stderr` at
        :data:`logging.INFO`::

           configure(logging.INFO, stream=sys.stderr)

        Send everything to a file, but keep the registry's bookkeeping out::

           configure(logging.DEBUG, handler=logging.FileHandler('pcapkit.log'))
           configure(logging.INFO, name='pcapkit.foundation.registry')

    """
    if stream is not None and handler is not None:
        raise ValueError("configure() accepts 'stream' or 'handler', not both")

    target = get_logger(name)

    if replace:
        _detach(target)
        if target is logger:
            target.addHandler(logging.NullHandler())

    if stream is None and handler is None and (fmt is not None or datefmt is not None):
        # a format was asked for, so output was clearly intended; honouring it
        # beats silently discarding the only argument the caller passed
        stream = sys.stderr

    if stream is not None:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter(fmt=fmt or DEFAULT_FORMAT,
                                               datefmt=datefmt or DEFAULT_DATE_FORMAT))
    elif handler is not None and (fmt is not None or datefmt is not None):
        handler.setFormatter(logging.Formatter(fmt=fmt or DEFAULT_FORMAT,
                                               datefmt=datefmt or DEFAULT_DATE_FORMAT))

    if handler is not None:
        target.addHandler(handler)
    if level is not None:
        target.setLevel(level)
    if propagate is not None:
        target.propagate = propagate
    return target


# NOTE: Import must not disturb configuration the application has already
# made -- that is the whole point of the NullHandler convention -- so this only
# guarantees the logger has *a* handler, and leaves level and propagation
# alone. Calling reset() here instead would detach a host application's
# handlers merely because it imported pcapkit after configuring logging.
#
# Re-execution has to be idempotent too, which the test suite relies on when it
# exercises import-time behaviour. That rules out an identity test for the
# devmode handler: ``handler`` is built when this module runs, so re-executing
# it yields a *new* object every time and ``handler not in logger.handlers``
# would be true on each pass, stacking one stderr handler per reload. The test
# is therefore on what would actually duplicate -- a stream handler already
# writing to the same stream.
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


def _writes_to(candidate: 'logging.Handler', stream: 'Any') -> 'bool':
    """Whether ``candidate`` is a stream handler already writing to ``stream``."""
    return isinstance(candidate, logging.StreamHandler) and getattr(candidate, 'stream', None) is stream


if DEVMODE:
    # development mode keeps the historical behaviour: everything, on stderr
    logger.setLevel(logging.DEBUG)
    if not any(_writes_to(installed, handler.stream) for installed in logger.handlers):
        logger.addHandler(handler)
