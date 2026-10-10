# -*- coding: utf-8 -*-
"""Registry Helpers
======================

.. module:: pcapkit.interface.registry

:mod:`pcapkit.interface.registry` contains the helpers the
registrars use to compare registry entries and to put back
the entry a registry shipped with, so that an override of a
built-in can be undone (:issue:`1363`, :issue:`1364`).

"""
import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any

__all__ = ['same_entry', 'restore_shipped', 'restore_shipped_dumper']


def same_entry(entry: 'Any', other: 'Any') -> 'bool':
    """Tell whether two registry entries name the same class.

    An entry is a class or a :class:`~pcapkit.corekit.module.ModuleDescriptor`.
    Two descriptors are the same entry when they are equal, and a descriptor
    and a class are when the descriptor names that class. The class is looked
    up in :data:`sys.modules` rather than imported: a class someone holds has
    its module loaded already, so a descriptor whose module is not loaded
    cannot name it, and an optional engine that is not installed is never
    imported to answer the question.

    The comparison is symmetric, and two classes are the same entry only when
    they are the same object.

    Arguments:
        entry: registry entry
        other: registry entry to compare against

    Returns:
        :data:`True` if both name the same class.

    """
    if entry is other:
        return True
    if isinstance(entry, ModuleDescriptor) and isinstance(other, ModuleDescriptor):
        return entry == other
    if isinstance(other, ModuleDescriptor):
        entry, other = other, entry
    if not isinstance(entry, ModuleDescriptor) or not isinstance(entry.name, str):
        return False
    module = sys.modules.get(entry.module)
    return module is not None and getattr(module, entry.name, None) is other


def restore_shipped(registry: 'dict[str, Any]', key: 'str', shipped: 'Any', kind: 'str') -> 'None':
    """Put the entry ``registry`` shipped with back under ``key``.

    The public registrars call this when handed the built-in that shipped under
    ``key``, so an override can be undone (:issue:`1363`). It stores the shipped
    object itself, a descriptor if a descriptor shipped, and it is a silent
    no-op when the incumbent already names the shipped class, as decided by
    :func:`same_entry`.

    Arguments:
        registry: registry to restore
        key: registry key
        shipped: entry the registry shipped with under ``key``
        kind: entry kind, for the warning message

    Warns:
        RegistryWarning: If a different class is registered under ``key``; it
            is overwritten.

    """
    incumbent = registry.get(key)
    if incumbent is not None and same_entry(shipped, incumbent):
        return
    if incumbent is not None:
        warn(f'{kind} {key} already registered, overwriting', RegistryWarning)
    registry[key] = shipped


def restore_shipped_dumper(registry: 'dict[str, Any]', format: 'str',  # pylint: disable=redefined-builtin
                           shipped: 'tuple[Any, str | None]', ext: 'str') -> 'None':
    """Put the dumper ``registry`` shipped with back under ``format``.

    The ``__output__`` counterpart of :func:`restore_shipped`: an entry is a
    ``(dumper, ext)`` pair, so the shipped pair itself is stored when ``ext``
    matches it, and the shipped dumper with the new ``ext`` otherwise. A
    re-registration that only changes ``ext`` stays silent, as the dumper
    registrars document.

    The incumbent is read with :meth:`dict.get`, so an ``__output__`` that is a
    :class:`collections.defaultdict` gains no entry from the lookup.

    Arguments:
        registry: ``__output__`` registry to restore
        format: format name
        shipped: ``(dumper, ext)`` pair the registry shipped with under ``format``
        ext: file extension

    Warns:
        RegistryWarning: If a different dumper is registered for ``format``;
            it is overwritten.

    """
    incumbent = registry.get(format)
    if incumbent is not None and not same_entry(shipped[0], incumbent[0]):
        warn(f'dumper {format} already registered, overwriting', RegistryWarning)
    elif incumbent is not None and incumbent[1] == ext:
        return
    registry[format] = shipped if ext == shipped[1] else (shipped[0], ext)
