# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Application Layer Protocol Numbers Constant Enumerations
============================================================

.. module:: pcapkit.const.reg.apptype

This module contains the constant enumerations for the **Application Layer
Protocol Numbers** registry. IANA keys every assignment on a ``(service, port,
transport)`` triple, so the registry is one enumeration per transport protocol,
sharing the transport-agnostic base they all subclass. Available enumerations
include:

.. list-table::

   * - :class:`AppType <pcapkit.const.reg.apptype.apptype.AppType>`
     - Application Layer Protocol Numbers (base registry, no members) [*]_
   * - :class:`TCP <pcapkit.const.reg.apptype.tcp.TCP>`
     - Application Layer Protocol Numbers (TCP)
   * - :class:`UDP <pcapkit.const.reg.apptype.udp.UDP>`
     - Application Layer Protocol Numbers (UDP)
   * - :class:`SCTP <pcapkit.const.reg.apptype.sctp.SCTP>`
     - Application Layer Protocol Numbers (SCTP)
   * - :class:`DCCP <pcapkit.const.reg.apptype.dccp.DCCP>`
     - Application Layer Protocol Numbers (DCCP)

.. [*] https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?

:class:`~pcapkit.const.reg.apptype.apptype.AppType` holds no members. It is the
type every member is an instance of, so ``isinstance(TCP.http, AppType)`` holds
and a caller that only has a port and a transport protocol can still reach the
right registry through :meth:`AppType.get
<pcapkit.const.reg.apptype.apptype.AppType.get>`.

:class:`~pcapkit.const.reg.apptype.tcp.TCP` and
:class:`~pcapkit.const.reg.apptype.udp.UDP` are imported the first time either
is reached -- as an attribute of this package, or through :meth:`AppType.get
<pcapkit.const.reg.apptype.apptype.AppType.get>` -- rather than with the package
itself, since they are most of its import time (GitHub issue :issue:`1538`).

"""

import importlib
from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype.apptype import AppType, TransportProtocol
from pcapkit.const.reg.apptype.dccp import DCCP
from pcapkit.const.reg.apptype.sctp import SCTP
from pcapkit.corekit.module import ModuleDescriptor

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.const.reg.apptype.tcp import TCP
    from pcapkit.const.reg.apptype.udp import UDP

__all__ = ['AppType', 'TransportProtocol', 'TCP', 'UDP', 'SCTP', 'DCCP']

#: Registries imported on first use rather than with this package, as submodule
#: name to class name -- GitHub issue :issue:`1538`. Generated from IANA's
#: registry, the two hold about 49,700 lines of members and were about 30% of
#: ``import pcapkit``, while SCTP's and DCCP's cost a few milliseconds and stay
#: eager.
_LAZY = {'tcp': 'TCP', 'udp': 'UDP'}


class _Registries(dict):
    """:attr:`AppType.__registries__ <pcapkit.const.reg.apptype.apptype.AppType.__registries__>`,
    importing a lazy registry the first time its value is read.

    Every key is present from the start, in the order the eager imports used to
    insert them, so :func:`len`, ``in`` and iteration import nothing. A lazy
    registry's value is a :class:`~pcapkit.corekit.module.ModuleDescriptor`
    until the first read replaces it with the class. Every way of reading a
    value is overridden, :meth:`__iter__` included: overriding it is what makes
    ``dict(...)`` and ``{**...}`` go through :meth:`__getitem__` instead of
    copying the descriptors in C, so no caller ever sees one.

    """

    __slots__ = ()

    def _resolve(self, key: 'Any', value: 'Any') -> 'Any':
        if isinstance(value, ModuleDescriptor):
            value = value.klass
            dict.__setitem__(self, key, value)
        return value

    def _resolve_all(self) -> 'None':
        for key, value in list(dict.items(self)):
            self._resolve(key, value)

    def __getitem__(self, key: 'Any') -> 'Any':
        return self._resolve(key, dict.__getitem__(self, key))

    def get(self, key: 'Any', default: 'Any' = None) -> 'Any':
        value = dict.get(self, key, default)
        # NOTE: the second test keeps a caller's own ``default`` from being
        # resolved and stored, should it ever be a descriptor itself.
        if isinstance(value, ModuleDescriptor) and dict.__contains__(self, key):
            value = self._resolve(key, value)
        return value

    def __iter__(self) -> 'Any':
        return dict.__iter__(self)

    def values(self) -> 'Any':
        self._resolve_all()
        return dict.values(self)

    def items(self) -> 'Any':
        self._resolve_all()
        return dict.items(self)

    def copy(self) -> 'dict[Any, Any]':
        self._resolve_all()
        return dict.copy(self)

    def pop(self, *args: 'Any') -> 'Any':
        self._resolve_all()
        return dict.pop(self, *args)

    def popitem(self) -> 'Any':
        self._resolve_all()
        return dict.popitem(self)

    def setdefault(self, key: 'Any', default: 'Any' = None) -> 'Any':
        self._resolve_all()
        return dict.setdefault(self, key, default)

    def __eq__(self, other: 'object') -> 'bool':
        self._resolve_all()
        return dict.__eq__(self, other)

    def __ne__(self, other: 'object') -> 'bool':
        self._resolve_all()
        return dict.__ne__(self, other)

    def __or__(self, other: 'Any') -> 'Any':
        self._resolve_all()
        return dict.__or__(self, other)

    def __ror__(self, other: 'Any') -> 'Any':
        self._resolve_all()
        return dict.__ror__(self, other)

    def __repr__(self) -> 'str':
        self._resolve_all()
        return dict.__repr__(self)


# NOTE: this is what makes ``AppType.get(port, proto=...)`` work on the base
# class, which is where every caller in the library addresses it. It cannot live
# in ``apptype.py``: that module is imported *by* all four registries, so it
# cannot import them back. Here is the first point at which all four exist, or
# for the lazy two, where to import them from.
AppType.__registries__ = _Registries({
    TransportProtocol.tcp: ModuleDescriptor(f'{__name__}.tcp', _LAZY['tcp']),
    TransportProtocol.udp: ModuleDescriptor(f'{__name__}.udp', _LAZY['udp']),
    TransportProtocol.sctp: SCTP,
    TransportProtocol.dccp: DCCP,
})


def __getattr__(name: 'str') -> 'Any':
    """Import a :data:`_LAZY` registry, or its submodule, on first access.

    :pep:`562` calls this only for a name missing from this module's globals,
    so it runs once per name: importing a submodule binds it here, and the
    class is bound here before it is returned.

    """
    if name in _LAZY:
        return importlib.import_module(f'{__name__}.{name}')
    module = name.lower()
    if _LAZY.get(module) == name:
        registry = getattr(importlib.import_module(f'{__name__}.{module}'), name)
        globals()[name] = registry
        return registry
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')


def __dir__() -> 'list[str]':
    """The names an eager import of all four registries would list."""
    helpers = {'importlib', 'TYPE_CHECKING', 'ModuleDescriptor', '_LAZY', '_Registries',
               '__getattr__', '__dir__'}
    return sorted({*globals(), *_LAZY, *_LAZY.values()} - helpers)
