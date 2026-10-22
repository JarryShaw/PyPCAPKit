# -*- coding: utf-8 -*-

import pathlib
import sys
from builtins import ModuleNotFoundError
from collections.abc import Collection
from functools import cached_property
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterator, Optional

__all__ = [
    # functions
    'final', 'localcontext', 'show_flag_values', 'default_threading_excepthook', 'unquote', 'get_annotations',

    # exceptions
    'ModuleNotFoundError',

    # classes
    'Collection', 'cached_property',
    'StrEnum', 'auto',

    # modules
    'pathlib',

    # typing
    'Mapping', 'Tuple', 'List', 'Dict', 'TypeAlias', 'UnionType',
]

# PyPy 8.0 binds ``NoneType`` in :mod:`builtins`, which CPython does not, and
# its own stdlib relies on it (``_sqlite3``, which aenum imports). aenum 3.1.17's
# ``_common`` binds a ``NoneType`` of its own only on a ``NameError``, so there it
# binds none, and the ``from ._common import *`` in aenum's ``__init__`` fails on
# the name ``__all__`` lists: ``AttributeError: module 'aenum._common' has no
# attribute 'NoneType'``. That left pcapkit unimportable on PyPy 8.0 (#1958).
# ``aenum._common`` itself ran to its end and stays in :data:`sys.modules`, so
# binding the name there and importing aenum again completes it, leaving
# :mod:`builtins` as PyPy has it. This module runs before any of pcapkit's that
# imports aenum: pcapkit/__init__.py reaches it through
# pcapkit.utilities.exceptions, ahead of pcapkit.corekit.
if sys.implementation.name == 'pypy':
    try:
        import aenum  # pylint: disable=unused-import
    except AttributeError:
        sys.modules['aenum._common'].NoneType = type(None)  # type: ignore[attr-defined]
        import aenum  # pylint: disable=unused-import

if sys.version_info < (3, 9):
    from typing import Dict, List, Mapping, Tuple
else:
    from collections.abc import Mapping

    Tuple: 'TypeAlias' = tuple
    List: 'TypeAlias' = list
    Dict: 'TypeAlias' = dict

# urllib.parse.unquote accepts bytes from 3.9; before it, it raises
# ``TypeError: Expected str, got bytes`` on them (issue #1693)
if sys.version_info < (3, 9):
    from urllib.parse import unquote as _unquote
    from urllib.parse import unquote_to_bytes as _unquote_to_bytes

    def unquote(string: 'str | bytes', encoding: 'str' = 'utf-8', errors: 'str' = 'replace') -> 'str':
        """Replace %xx escapes by their single-character equivalent. The optional
        encoding and errors parameters specify how to decode percent-encoded
        sequences into Unicode characters, as accepted by the bytes.decode()
        method. A bytes string is unquoted to octets first and then decoded,
        as from Python 3.9; anything else goes to this interpreter's own
        unquote unchanged."""
        if isinstance(string, bytes):
            return _unquote_to_bytes(string).decode(encoding, errors)
        return _unquote(string, encoding, errors)
else:
    from urllib.parse import unquote

# The ``else`` branch of each ``sys.version_info`` guard below imports a name
# that only exists on the newer interpreter, so it never executes on the older
# one the guard is there to support. Vermin's analysis is static and cannot see
# that, so it counts these imports anyway and reports the whole library as
# requiring 3.11 on the strength of lines that never run below it.
# ``# novermin`` is Vermin's documented escape hatch for precisely this shape.
# It is applied per line rather than by turning on ``lax`` mode, so that an
# *unguarded* use of a new feature anywhere else is still caught.
#
# ``auto`` rides the same branch as ``StrEnum`` rather than a guard of its own,
# because the two are not interchangeable across implementations: an
# ``aenum.auto`` value in a stdlib ``enum.StrEnum`` class body raises
# ``TypeError: auto(<no_value>, *(), **{}) is not a string``, and an
# ``enum.auto`` value in an ``aenum.StrEnum`` body raises ``TypeError: values
# must be str [auto(_auto_null) is a <class 'enum.auto'>]`` (both measured) --
# each metaclass only recognises its own library's sentinel class. Splitting
# ``auto`` onto a second, parallel ``sys.version_info`` check would let it
# drift from whichever library ``StrEnum`` actually resolved to; sharing this
# branch makes that impossible by construction.
if sys.version_info < (3, 11):
    from aenum import StrEnum, auto
else:
    from enum import StrEnum, auto  # novermin

# The guard is 3.11 rather than 3.8, which is when the *name* arrived, because
# what this library needs from ``final`` is not the name but the side effect:
# from 3.11 on (gh-90500) ``typing.final`` records ``__final__ = True`` on the
# decorated object, and before that it is a pure annotation for the type checker
# leaving no runtime trace at all. That dunder is *read* --
# :meth:`pcapkit.corekit.infoclass.Info.__init_subclass__` and
# :meth:`pcapkit.protocols.schema.schema.Schema.__init_subclass__` refuse to
# derive from a class carrying it in its own ``__dict__`` -- so on 3.10, which is
# in the CI matrix, keying the guard on 3.8 would leave the runtime check reading
# an attribute nothing had set: a silent no-op on one supported interpreter and
# an enforced rule on the rest. ``typing_extensions`` is a declared dependency
# for exactly ``python_version < '3.11'`` and its ``final`` sets the attribute on
# every version, so asking for it below 3.11 costs nothing and closes the gap.
if sys.version_info < (3, 11):
    from typing_extensions import final
else:
    from typing import final

if sys.version_info < (3, 11):
    from contextlib import contextmanager
    from decimal import localcontext as _localcontext

    if TYPE_CHECKING:
        from decimal import Context
        from types import TracebackType

        class _ContextManager:
            def __init__(self, new_context: Context) -> None: ...
            def __enter__(self) -> Context: ...
            def __exit__(self, t: type[BaseException] | None, v: BaseException | None, tb: TracebackType | None) -> None: ...

    @contextmanager
    def localcontext(ctx: 'Optional[Context]' = None, **kwargs: 'Any') -> '_ContextManager':
        """Return a context manager that will set the default context to a copy
        of ctx on entry to the with-statement and restore the previous default
        context when exiting the with-statement. If no context is specified, a
        copy of the current default context is used."""
        with _localcontext(ctx) as lc:
            for attr, value in kwargs.items():
                setattr(lc, attr, value)
            yield lc
else:
    from decimal import localcontext

if sys.version_info < (3, 11):
    from enum import Enum

    if TYPE_CHECKING:
        from enum import IntFlag

    def _iter_bits_lsb(num: 'int') -> 'Iterator[int]':
        # num must be a positive integer
        original = num
        if isinstance(num, Enum):
            num = num.value
        if num < 0:
            raise ValueError('%r is not a positive integer' % original)
        while num:
            b = num & (~num + 1)
            yield b
            num ^= b

    def show_flag_values(value: 'IntFlag') -> 'list[int]':
        return list(_iter_bits_lsb(value))
else:
    from enum import show_flag_values  # type: ignore[attr-defined]  # novermin

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias  # novermin

# The interpreter's own default :data:`threading.excepthook`, as it stood before
# anything replaced it, which :data:`threading.__excepthook__` names only from
# 3.10 (issue #1691). The object itself is older: CPython 3.8 and 3.9 start
# :data:`threading.excepthook` as ``_thread._excepthook``, the same function 3.10
# and later bind as ``__excepthook__`` (checked with ``is`` on 3.8.20, 3.9.25,
# 3.10.21 and 3.14.8). Importing it from :mod:`_thread`, rather than reading
# whatever :data:`threading.excepthook` holds when this module loads, keeps it the
# real default on 3.8 and 3.9 even when a host application, or an earlier loaded
# copy of :mod:`pcapkit.utilities.exceptions`, has already replaced the hook --
# as it is on 3.10 and later.
#
# The stdlib name is not reused as it stands, unlike every other name here: a
# bare ``__excepthook__`` imported into a module reads as
# :data:`sys.__excepthook__`, which takes three arguments rather than one, and
# :mod:`pcapkit.utilities.exceptions` uses both. ``default_`` is the word that
# module's docstrings already use for this object.
if sys.version_info < (3, 10):
    from _thread import _excepthook as default_threading_excepthook
else:
    from threading import __excepthook__ as default_threading_excepthook  # novermin

# A class's own annotations, never a base's (issue #1692). Below 3.10
# (bpo-43901), ``cls.__annotations__`` of a class whose body declares none is
# its nearest base's, so the fallback reads the class's own ``__dict__``, where
# its body put them, and returns that mapping itself rather than a copy.
# :func:`inspect.get_annotations` reads the same place for a class on 3.10 to
# 3.13; from 3.14 a body without ``from __future__ import annotations`` leaves
# them out of ``__dict__``, so it is the only reader that sees them. Only what
# this library asks of it is backported: a class, without ``globals``,
# ``locals`` or ``eval_str``.
if sys.version_info < (3, 10):
    def get_annotations(obj: 'type') -> 'dict[str, Any]':
        """Return the annotations a class's own body declares, which may be empty."""
        return obj.__dict__.get('__annotations__', {})
else:
    from inspect import get_annotations  # novermin

# The :pep:`604` union type, i.e. the origin of ``int | None``, which is the
# same object as :data:`typing.Union` from 3.14. Below 3.10 only
# :data:`typing.Union` spells a union, so the name is :data:`None` there rather
# than a failed import.
if sys.version_info < (3, 10):
    UnionType = None
else:
    from types import UnionType  # novermin
