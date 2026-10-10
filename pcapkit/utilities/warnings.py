# -*- coding: utf-8 -*-
"""User Defined Warnings
===========================

.. module:: pcapkit.utilities.warnings

:mod:`pcapkit.utilities.warnings` refined built-in warnings.

Every warning :mod:`pcapkit` reports goes through :func:`warn`, which reports it
**exactly once on each of two channels**:

1. the :data:`~pcapkit.utilities.logging.logger` logger, at
   :data:`logging.WARNING` level, unconditionally -- so a consumer watching the
   ``pcapkit`` logger sees every complaint whatever the warning filters say;
2. the standard :mod:`warnings` machinery, via :func:`warnings.warn`, subject to
   the filters -- so :func:`warnings.filterwarnings`,
   :func:`warnings.catch_warnings`, :mod:`pytest`'s ``filterwarnings``,
   :option:`-W` and :envvar:`PYTHONWARNINGS` govern :mod:`pcapkit` warnings
   exactly as they govern any other library's (see below for the one wrinkle in
   naming a category on the command line).

The counts are the same in development mode as outside it;
:data:`~pcapkit.utilities.logging.DEVMODE` and
:data:`~pcapkit.utilities.logging.VERBOSE` change how much detail the log record
carries, never how many records there are. Constructing a warning class is not
an act of reporting one, and has no side effects at all.

To silence :mod:`pcapkit` warnings, filter them like any other category::

    import warnings

    from pcapkit.utilities.warnings import BaseWarning

    warnings.filterwarnings('ignore', category=BaseWarning)

From the command line, name one of the standard categories these are mixed with
-- :exc:`UserWarning` covers all of them, and :exc:`RuntimeWarning`,
:exc:`ImportWarning`, :exc:`ResourceWarning` and :exc:`DeprecationWarning` each
select a family::

    python -W ignore::UserWarning ...

:option:`-W` and :envvar:`PYTHONWARNINGS` cannot name a :mod:`pcapkit` category
directly -- ``-W ignore::pcapkit.utilities.warnings.BaseWarning`` is rejected
with ``Invalid -W option ignored: invalid module name``. CPython imports the
category while parsing the option, which happens before :mod:`site` has added
``site-packages`` to :data:`sys.path`, so no installed package's own category can
be named there; this is not specific to :mod:`pcapkit`.

Note that all of the above governs the :mod:`warnings` channel only. The
``pcapkit`` logger is configured separately, e.g. with
``logging.getLogger('pcapkit').setLevel(logging.ERROR)``.

The one exception is a parse :mod:`pcapkit` runs on trial: :class:`hold_warnings`
holds back its warnings, on both channels, until the parse is kept, and drops
them if it is discarded (:issue:`1580`).

"""
import contextvars
import inspect
import warnings
from typing import TYPE_CHECKING

from pcapkit.utilities.exceptions import stacklevel as stacklevel_calculator
from pcapkit.utilities.logging import VERBOSE, get_logger

if TYPE_CHECKING:
    from types import FrameType, TracebackType
    from typing import List, Optional, Tuple, Type, Union

    from typing_extensions import Self

    #: A warning held back by :class:`hold_warnings`: its message, its category,
    #: and the frame it is attributed to, if that frame could be found.
    HeldWarning = Tuple[Union[str, Warning], Type[Warning], Optional[FrameType]]

__all__ = [
    'warn',

    # UserWarning
    'BaseWarning',
    # ImportWarning
    'FormatWarning', 'EngineWarning', 'InvalidVendorWarning',
    # RuntimeWarning
    'FileWarning', 'LayerWarning', 'ProtocolWarning', 'AttributeWarning',
    'DevModeWarning', 'VendorRequestWarning', 'VendorRuntimeWarning',
    'UnknownFieldWarning', 'RegistryWarning', 'SchemaWarning', 'InfoWarning',
    'SeekWarning', 'ExtractionWarning',
    # ResourceWarning
    'DPKTWarning', 'ScapyWarning', 'PySharkWarning', 'EmojiWarning',
    'VendorWarning',
    # DeprecationWarning
    'DeprecatedFormatWarning',
]


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)

#: The innermost open :class:`hold_warnings` block, or :data:`None` outside any.
#: A context variable rather than a global, so that a parse in another thread or
#: task is neither held nor released by this one.
_HELD = contextvars.ContextVar(
    'pcapkit_held_warnings', default=None)  # type: contextvars.ContextVar[Optional[hold_warnings]]


def warn(message: 'Union[str, Warning]', category: 'Type[Warning]',
         stacklevel: 'Optional[int]' = None) -> 'None':
    """Wrapper function of :func:`warnings.warn`.

    The warning is reported once on the :data:`~pcapkit.utilities.logging.logger`
    logger, then once through :func:`warnings.warn`. The logger call does not
    consult :data:`warnings.filters`, so a log-based consumer sees the complaint
    even when the application has filtered the category out; the
    :func:`warnings.warn` call is filtered normally, so the application keeps
    full control of that channel -- including turning the warning into an error
    with :option:`-W error <-W>`.

    Args:
        message: Warning message.
        category: Warning category.
        stacklevel: Warning stack level, **relative to the caller of this
            function** -- ``1`` blames the line that called :func:`warn`, ``2``
            its caller, and so on, exactly as the argument of the same name reads
            on :func:`warnings.warn` itself. Defaults to
            :func:`~pcapkit.utilities.exceptions.stacklevel`, i.e. the innermost
            frame outside :mod:`pcapkit`.

    See Also:
        :mod:`pcapkit.utilities.warnings` for the emission model in full, and for
        how to silence either channel.

    Note:
        Inside a :class:`hold_warnings` block the warning is held back instead,
        with the frame it is attributed to, and reported from there only if the
        block keeps it.

    """
    if stacklevel is None:
        # Computed here, so the level is already relative to *this* frame, which
        # is the frame both consumers below count outwards from. Used as is.
        stacklevel = stacklevel_calculator()
    else:
        # A caller-supplied level is relative to the caller's frame, one deeper
        # than this one, so this frame has to be added back before forwarding --
        # the ordinary convention for a function wrapping `warnings.warn`. Without
        # it, `warn(..., stacklevel=stacklevel())` at a call site lands one frame
        # short of the boundary, i.e. still inside pcapkit, which is the frame the
        # whole exercise exists to skip past.
        stacklevel += 1

    block = _open_block(_HELD.get())
    if block is not None and block.holding:
        # Level 1 is this frame, so the frame named is ``stacklevel - 1`` out.
        target = inspect.currentframe()
        for _ in range(stacklevel - 1):
            if target is None:
                break
            target = target.f_back
        block._held.append((message, category, target))  # pylint: disable=protected-access
        del target
        return

    logger.warning(message, exc_info=VERBOSE, stack_info=VERBOSE,
                   stacklevel=stacklevel)
    warnings.warn(message, category, stacklevel)


def _open_block(block: 'Optional[hold_warnings]') -> 'Optional[hold_warnings]':
    """The innermost open block from ``block`` outwards.

    Args:
        block: Block to start from, usually the one :data:`_HELD` names.

    Returns:
        ``block``, or the nearest block enclosing it that is still open. A block
        is left closed but still named only when it was left out of order, or in
        another context, where it could not unset itself in this one.

    """
    while block is not None and not block._open:  # pylint: disable=protected-access
        block = block._outer  # pylint: disable=protected-access
    return block


def _replay(message: 'Union[str, Warning]', category: 'Type[Warning]',
            target: 'Optional[FrameType]') -> 'None':
    """Report a warning :class:`hold_warnings` held back, as :func:`warn` would have.

    Args:
        message: Warning message.
        category: Warning category.
        target: Frame the warning was attributed to when it was held.

    The warning is attributed to ``target`` again, found by walking out from this
    frame. ``target`` lies outside the parse that held it whenever its level came
    from :func:`~pcapkit.utilities.exceptions.stacklevel`, and so is still on the
    stack; were it not, the level is computed afresh. It is reported here and
    now, not held again by an enclosing block.

    """
    level = 1  # this frame, as both consumers below count it
    frame = inspect.currentframe()
    while frame is not None and frame is not target:
        frame = frame.f_back
        level += 1
    found = frame is not None
    del frame
    if not found:
        level = stacklevel_calculator()

    logger.warning(message, exc_info=VERBOSE, stack_info=VERBOSE, stacklevel=level)
    warnings.warn(message, category, level)


class hold_warnings:  # pylint: disable=invalid-name
    """Hold back the warnings a parse reports until it is known to be kept.

    Args:
        hold: Hold the warnings reported inside the block. When false, they are
            reported at once instead, even inside an enclosing block that holds.

    Every :func:`warn` call inside the block is held, with the frame it is
    attributed to. On leaving the block they are reported in order, with the
    same message and category and attributed to the same frame on both
    channels, unless :attr:`discard` was set, in which case they are dropped. A
    block left by an :exc:`Exception` reports them whatever :attr:`discard`
    says; one left by any other :exc:`BaseException` -- :exc:`KeyboardInterrupt`,
    :exc:`SystemExit`, :exc:`GeneratorExit` -- drops them, so that a filter
    turning them into errors cannot replace it.

    The line named is the frame's line when the block is left. For the frame
    :func:`~pcapkit.utilities.exceptions.stacklevel` names -- the caller of
    :mod:`pcapkit`, still inside that call -- it is the line named when held.

    Blocks nest, and each reports what it keeps when it is left, never handing
    it to an enclosing block. Under a filter turning warnings into errors, the
    error is then raised where the block that kept them is left -- the end of
    the trial parse, inside the guard it was raised in when nothing was held.

    :meth:`ProtocolBase._parse_next_layer
    <pcapkit.protocols.protocol.ProtocolBase._parse_next_layer>` uses this for the
    trial parse it replaces with :class:`~pcapkit.protocols.misc.raw.Raw` when the
    header was not captured: the warnings describe a layer the result does not
    have (:issue:`1580`).

    Note:
        Nothing here touches :data:`warnings.filters` or a module's
        ``__warningregistry__``; :func:`warnings.catch_warnings` would, which is
        what made unrelated warnings re-fire up to v1.4.1 (see
        :class:`BaseWarning`).

        A block left while one opened inside it is still open -- a generator
        suspended inside its own block -- stays in place for that one, which
        steps over it when it is left. While it is suspended, though, the
        generator's block holds its caller's warnings too: a context variable
        follows the thread, not the frame.

    """

    __slots__ = ('discard', 'holding', '_held', '_outer', '_token', '_open')

    def __init__(self, hold: 'bool' = True) -> 'None':
        #: Drop the held warnings on leaving the block, rather than report them.
        self.discard = False
        #: Whether warnings reported inside the block are held.
        self.holding = hold

        self._held = []  # type: List[HeldWarning]
        self._outer = None  # type: Optional[hold_warnings]
        self._token = None  # type: Optional[contextvars.Token[Optional[hold_warnings]]]
        self._open = False

    def __enter__(self) -> 'Self':
        self._held = []
        self._outer = _HELD.get()
        self._token = _HELD.set(self)
        self._open = True
        return self

    def __exit__(self, exc_type: 'Optional[Type[BaseException]]',
                 exc_value: 'Optional[BaseException]',
                 traceback: 'Optional[TracebackType]') -> 'None':
        token, self._token = self._token, None
        # a block opened inside this one and still open -- a suspended generator's
        # -- stays in place, and steps over this one when it is left in turn
        innermost = _open_block(_HELD.get()) is self
        self._open = False
        if innermost and token is not None:
            try:
                _HELD.reset(token)
            except ValueError:  # left in a copy of the context it was entered in
                _HELD.set(self._outer)
            outer = _open_block(_HELD.get())
            if outer is not _HELD.get():
                _HELD.set(outer)

        held, self._held = self._held, []
        if self.discard and exc_type is None:
            return
        if exc_type is not None and not issubclass(exc_type, Exception):
            return
        for message, category, target in held:
            _replay(message, category, target)


##############################################################################
# BaseWarning (abc of warnings) session.
##############################################################################


class BaseWarning(UserWarning):
    """Base warning class of all kinds.

    Constructing one of these is deliberately free of side effects: it emits
    nothing and mutates no process-global state. Reporting a warning is the job
    of :func:`warn`, which is called once per complaint; a warning object may be
    built without ever being reported, and the two must not be confused.

    Note:
        Up to and including v1.4.1, this constructor called
        ``warnings.simplefilter('ignore', type(self))`` outside development
        mode, which inserted an entry at the front of the process-global
        :data:`warnings.filters` -- overriding whatever the host application,
        :option:`-W` or the test runner had configured, and invalidating every
        module's ``__warningregistry__`` so that unrelated warnings re-fired.
        It also logged the warning a second time under
        :data:`~pcapkit.utilities.logging.DEVMODE`. Both are gone; filtering is
        the application's business, and is done through the standard
        :mod:`warnings` machinery.

    """


##############################################################################
# ImportWarning session.
##############################################################################


class FormatWarning(BaseWarning, ImportWarning):
    """Warning on unknown format(s)."""


class EngineWarning(BaseWarning, ImportWarning):
    """Unsupported extraction engine."""


class InvalidVendorWarning(BaseWarning, ImportWarning):
    """Vendor CLI invalid updater."""


##############################################################################
# RuntimeWarning session.
##############################################################################


class FileWarning(BaseWarning, RuntimeWarning):
    """Warning on file(s)."""


class LayerWarning(BaseWarning, RuntimeWarning):
    """Unrecognised layer."""


class ProtocolWarning(BaseWarning, RuntimeWarning):
    """Unrecognised protocol."""


class AttributeWarning(BaseWarning, RuntimeWarning):
    """Unsupported attribute."""


class DevModeWarning(BaseWarning, RuntimeWarning):
    """Run in development mode."""


class VendorRequestWarning(BaseWarning, RuntimeWarning):
    """Vendor request connection failed."""


class VendorRuntimeWarning(BaseWarning, RuntimeWarning):
    """Vendor failed during runtime."""


class UnknownFieldWarning(BaseWarning, RuntimeWarning):
    """Unknown field."""


class RegistryWarning(BaseWarning, RuntimeWarning):
    """Registry warning."""


class SchemaWarning(BaseWarning, RuntimeWarning):
    """Schema warning."""


class InfoWarning(BaseWarning, RuntimeWarning):
    """Info class warning."""


class SeekWarning(BaseWarning, RuntimeWarning):
    """Seek operation warning."""


class ExtractionWarning(BaseWarning, RuntimeWarning):
    """Extraction warning."""


##############################################################################
# ResourceWarning session.
##############################################################################


class DPKTWarning(BaseWarning, ResourceWarning):
    """Warnings on DPKT usage."""


class ScapyWarning(BaseWarning, ResourceWarning):
    """Warnings on Scapy usage."""


class PySharkWarning(BaseWarning, ResourceWarning):
    """Warnings on PyShark usage."""


class EmojiWarning(BaseWarning, ResourceWarning):
    """Warnings on Emoji usage."""


class VendorWarning(BaseWarning, ResourceWarning):
    """Warnings on vendor usage."""


##############################################################################
# DeprecationWarning session.
##############################################################################


class DeprecatedFormatWarning(BaseWarning, DeprecationWarning):
    """Warning on deprecated formats."""
