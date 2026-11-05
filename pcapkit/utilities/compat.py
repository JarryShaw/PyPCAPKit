# -*- coding: utf-8 -*-

import pathlib
import sys
from builtins import ModuleNotFoundError
from collections.abc import Collection
from functools import cached_property
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterator, Optional, Type

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

# PyPy 8.0 binds ``NoneType`` in ``builtins``, so aenum 3.1.17's ``_common``,
# which binds its own only on a ``NameError``, binds none, and importing aenum
# fails with ``AttributeError: module 'aenum._common' has no attribute
# 'NoneType'`` (#1958). ``aenum._common`` stays in ``sys.modules``, so binding the
# name there and importing again completes it. This module is imported before
# any pcapkit module that imports aenum.
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

# Vermin cannot see that the ``else`` branch of a ``sys.version_info`` guard never
# runs on the older interpreter, so each such import carries ``# novermin``, per
# line rather than ``lax`` mode, which would also hide an unguarded use.
#
# ``auto`` shares ``StrEnum``'s branch because each metaclass accepts only its
# own library's ``auto``: mixing them raises ``TypeError`` (measured both ways).
if sys.version_info < (3, 11):
    from aenum import StrEnum, auto
else:
    from enum import StrEnum, auto  # novermin

# The guard is 3.11, not 3.8, because only from 3.11 (gh-90500) does
# ``typing.final`` set ``__final__ = True``, which ``Info.__init_subclass__`` and
# ``Schema.__init_subclass__`` read to refuse a subclass; ``typing_extensions``,
# a dependency below 3.11, sets it on every version.
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
            def __exit__(self, t: Type[BaseException] | None, v: BaseException | None, tb: TracebackType | None) -> None: ...

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
    from enum import show_flag_values  # novermin

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias  # novermin

# The interpreter's default ``threading.excepthook``, which
# ``threading.__excepthook__`` names only from 3.10 (#1691). On 3.8 and 3.9 it is
# ``_thread._excepthook`` (checked with ``is`` on 3.8.20, 3.9.25, 3.10.21 and
# 3.14.8), imported from there so a hook replaced before this module loads is
# not taken for the default. Renamed, since a bare ``__excepthook__`` reads as
# ``sys.__excepthook__``, which ``pcapkit.utilities.exceptions`` also uses.
if sys.version_info < (3, 10):
    from _thread import _excepthook as default_threading_excepthook
else:
    from threading import __excepthook__ as default_threading_excepthook  # novermin

# A class's own annotations, never a base's (#1692). Below 3.10 (bpo-43901),
# ``cls.__annotations__`` of a class declaring none is its base's, so the backport
# reads the class's own ``__dict__``; from 3.14 only ``inspect.get_annotations``
# sees them. Only a class is backported, without ``globals``, ``locals`` or ``eval_str``.
if sys.version_info < (3, 10):
    def get_annotations(obj: 'type') -> 'dict[str, Any]':
        """Return the annotations a class's own body declares, which may be empty."""
        return obj.__dict__.get('__annotations__', {})
else:
    from inspect import get_annotations  # novermin

# The PEP 604 union type, the origin of ``int | None``, which is ``typing.Union``
# from 3.14; ``None`` below 3.10, where only ``typing.Union`` spells a union.
if sys.version_info < (3, 10):
    UnionType = None
else:
    from types import UnionType  # novermin
