# -*- coding: utf-8 -*-
"""Protocol Registry
=======================

.. module:: pcapkit.protocols.registry

:mod:`pcapkit.protocols.registry` builds :data:`pcapkit.protocols.__proto__`, the
registry of protocol classes by name, which :mod:`pcapkit.protocols` exports from
here. It names every protocol class that package exports, so importing it imports
them all; the package puts that off until the registry is first reached
(:issue:`2730`).

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit import protocols
from pcapkit.protocols.protocol import ProtocolBase

if TYPE_CHECKING:
    from typing import Type

__all__ = []  # type: list[str]

#: dict[str, ~typing.Type[~pcapkit.protocols.protocol.ProtocolBase]]: Protocol
#: registry, bound before it is filled so that a read while it is being built
#: finds this object.
__proto__ = {}  # type: dict[str, Type[ProtocolBase]]
for _name in protocols.__all__:
    _value = getattr(protocols, _name)
    if isinstance(_value, type) and issubclass(_value, ProtocolBase):
        __proto__[_name.upper()] = _value
