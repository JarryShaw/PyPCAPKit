# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Application Layer Protocol Numbers Constant Enumerations
==============================================================

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

Each per-transport registry -- :class:`~pcapkit.const.reg.apptype.tcp.TCP`,
:class:`~pcapkit.const.reg.apptype.udp.UDP`,
:class:`~pcapkit.const.reg.apptype.sctp.SCTP` and
:class:`~pcapkit.const.reg.apptype.dccp.DCCP` -- is imported the first time it
is reached, as an attribute of this package or through :meth:`AppType.get
<pcapkit.const.reg.apptype.apptype.AppType.get>`, rather than with the package
itself: TCP and UDP for being most of its import time (GitHub issue
:issue:`1538`), and SCTP and DCCP as every :mod:`pcapkit.const` enumeration is
(:issue:`2729`).

"""

import itertools
from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype.apptype import AppType, TransportProtocol
from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from typing import Any, ItemsView, Iterable, Iterator, Mapping, Optional, SupportsIndex, Type

    from pcapkit.const.reg.apptype.dccp import DCCP
    from pcapkit.const.reg.apptype.sctp import SCTP
    from pcapkit.const.reg.apptype.tcp import TCP
    from pcapkit.const.reg.apptype.udp import UDP
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = ['AppType', 'TransportProtocol', 'TCP', 'UDP', 'SCTP', 'DCCP']

#: Registries imported on first use rather than with this package, as public
#: name to submodule and class name: every per-transport registry (GitHub issues
#: :issue:`1538` and :issue:`2729`).
_LAZY = {'TCP': ('tcp', 'TCP'), 'UDP': ('udp', 'UDP'), 'SCTP': ('sctp', 'SCTP'), 'DCCP': ('dccp', 'DCCP')}


@info_final
class _Registries(Info['Type[AppType]']):
    """:attr:`AppType.__registries__ <pcapkit.const.reg.apptype.apptype.AppType.__registries__>`,
    importing a lazy registry the first time its value is read.

    An :class:`~pcapkit.corekit.infoclass.Info` keyed by
    :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol` members, in
    the order it is built from. Each registry is held under a name made from its
    member's, as an :class:`~pcapkit.corekit.infoclass.Info` holds a key named
    like one of its methods, and the ``__map__`` and ``__map_reverse__`` it keeps
    for those pair the two: a lookup by member or by bare :class:`int` finds the
    registry, and iteration yields the members. :func:`len`, ``in`` and
    iteration import nothing.

    A lazy registry is held as a :class:`~pcapkit.corekit.module.ModuleDescriptor`
    until the first read of its value replaces it with the class. Every read of a
    value -- indexing, ``get()``, ``values()``, ``items()``, ``==``,
    :func:`repr`, :meth:`to_dict`, a copy or a pickle -- goes through
    :meth:`__getitem__` or imports every registry first, so no caller ever sees a
    descriptor.

    It is immutable, as every :class:`~pcapkit.corekit.infoclass.Info` is, and no
    :obj:`dict` subclass (GitHub issue :issue:`2726`): it has none of the
    :obj:`dict` methods that change a mapping, nor ``copy()`` or the ``|``
    operator.

    """

    if TYPE_CHECKING:
        def __init__(self, dict_: 'Mapping[TransportProtocol, Type[AppType] | ModuleDescriptor[AppType]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long

    def __update__(self, dict_: 'Optional[Mapping[Any, Any] | Iterable[tuple[Any, Any]]]' = None,
                   **kwargs: 'Type[AppType] | ModuleDescriptor[AppType]') -> 'None':
        """Hold each registry under the name made from its transport protocol.

        Args:
            dict_: Registries, each keyed by a
                :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol`
                member, or by its value or name.
            **kwargs: More registries, each keyed by its transport protocol's name.

        """
        for (key, registry) in itertools.chain(dict(dict_ or ()).items(), kwargs.items()):
            proto = TransportProtocol.get(key)
            name = f'_{type(self).__name__}{proto.name}'
            self.__map__[proto] = name
            self.__map_reverse__[name] = proto
            self.__dict__[name] = registry

    def __getitem__(self, key: 'Any') -> 'Type[AppType]':
        # NOTE: ``__map__`` holds the transport protocols alone, so any other
        # key, the names of the bookkeeping attributes included, raises
        # :exc:`KeyError` as a missing :obj:`dict` key does.
        name = self.__map__[key]
        registry = self.__dict__[name]
        if isinstance(registry, ModuleDescriptor):
            registry = registry.klass
            self.__dict__[name] = registry
        return registry

    def __contains__(self, key: 'object') -> 'bool':
        return key in self.__map__

    def __repr__(self) -> 'str':
        return repr(dict(self.items()))

    __str__ = __repr__

    def __reduce_ex__(self, protocol: 'SupportsIndex') -> 'Any':
        self._resolve_all()
        return super().__reduce_ex__(protocol)

    def items(self, multi: 'bool' = False) -> 'ItemsView[str, Type[AppType]] | Iterator[tuple[str, Type[AppType]]]':  # type: ignore[override] # pylint: disable=line-too-long
        if multi:
            self._resolve_all()
        return super().items(multi)

    def to_dict(self) -> 'OrderedMultiDict[str, Type[AppType]]':
        self._resolve_all()
        return super().to_dict()

    def _resolve_all(self) -> 'None':
        """Import every pending registry, as reading each value does."""
        list(self.values())


# NOTE: this is what makes ``AppType.get(port, proto=...)`` work on the base
# class, which is where every caller in the library addresses it. It cannot live
# in ``apptype.py``: that module is imported *by* every per-transport registry,
# so it cannot import them back. Here is where to import each of them from.
AppType.__registries__ = _Registries({  # type: ignore[assignment] # Info types its keys as str
    TransportProtocol.get(module): ModuleDescriptor(f'{__name__}.{module}', klass)
    for (module, klass) in _LAZY.values()
})

__getattr__, __dir__ = lazy_exports(__name__, globals(), _LAZY)
