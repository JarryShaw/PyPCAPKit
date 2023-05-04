# -*- coding: utf-8 -*-
"""Multi-Mapping Dictionary
==============================

.. module:: pcapkit.corekit.multidict

:mod:`pcapkit.corekit.multidict` contains multi-mapping dictionary classes,
which are used to store multiple mappings of the same key. The implementation
is inspired and based on the `Werkzeug`_ project.

.. _Werkzeug: https://werkzeug.palletsprojects.com/

"""

import copy
from typing import TYPE_CHECKING, Generic, TypeVar, cast, overload

from pcapkit.utilities.exceptions import MissingKeyError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, Mapping, NoReturn, Optional, SupportsIndex

    from typing_extensions import Literal

__all__ = ['MultiDict', 'OrderedMultiDict']

###############################################################################
# Type variables
###############################################################################

_T = TypeVar('_T')
_KT = TypeVar('_KT')
_VT = TypeVar('_VT')

###############################################################################
# Internals
###############################################################################


class _omd_bucket(Generic[_KT, _VT]):
    """Wraps values in the :class:`OrderedMultiDict`.

    This makes it possible to keep an order over multiple different keys. It
    requires a lot of extra memory and slows down access a lit, but makes it
    possible to access elements in ``O(1)`` and iterate in ``O(n)``

    """
    prev: 'Optional[_omd_bucket]'
    next: 'Optional[_omd_bucket]'
    key: '_KT'
    value: '_VT'

    __slots__ = ('prev', 'key', 'value', 'next')

    def __init__(self, omd: 'OrderedMultiDict', key: '_KT', value: '_VT') -> 'None':
        self.prev = omd._last_bucket
        self.key = key
        self.value = value
        self.next = None

        if omd._first_bucket is None:
            omd._first_bucket = self
        if omd._last_bucket is not None:
            omd._last_bucket.next = self
        omd._last_bucket = self

    def unlink(self, omd: 'OrderedMultiDict') -> 'None':
        if self.prev:
            self.prev.next = self.next
        if self.next:
            self.next.prev = self.prev
        if omd._first_bucket is self:  # pylint: disable=protected-access
            omd._first_bucket = self.next  # pylint: disable=protected-access
        if omd._last_bucket is self:  # pylint: disable=protected-access
            omd._last_bucket = self.prev  # pylint: disable=protected-access


class _Missing:
    def __repr__(self) -> 'str':
        return "no value"

    def __reduce__(self) -> 'str':
        return "_missing"


_missing = _Missing()

###############################################################################
# Helpers
###############################################################################


def iter_multi_items(mapping: 'Mapping[_KT, _VT | Iterable[_VT]] | Iterable[tuple[_KT, _VT]]') -> 'Iterator[tuple[_KT, _VT]]':  # pylint: disable=line-too-long
    """Iterates over the items of a mapping yielding keys and values
    without dropping any from more complex structures.
    """
    if isinstance(mapping, MultiDict):
        yield from mapping.items(multi=True)
    elif isinstance(mapping, dict):
        for key, value in mapping.items():
            if isinstance(value, (tuple, list)):
                for v in value:
                    yield key, v
            else:
                yield key, value
    else:
        yield from mapping  # type: ignore[misc]


###############################################################################
# Data structures
###############################################################################


class MultiDict(dict, Generic[_KT, _VT]):
    """A :class:`MultiDict` is a dictionary subclass customized to deal with
    multiple values for the same key.

    :class:`MultiDict` implements all standard dictionary methods. Internally,
    it saves all values for a key as a list, but the standard :obj:`dict`
    access methods will only return the first value for a key. If you want to
    gain access to the other values, too, you have to use the :meth:`getlist`
    and similar methods.

    Args:
        mapping: The initial value for the :class:`MultiDict`. Either a
            regular :obj:`dict`, an iterable of ``(key, value)`` tuples, or
            :obj:`None`.

    It behaves like a normal :obj:`dict` thus all :obj:`dict` functions will
    only return the first value when multiple values for one key are found.

    See Also:
        The class is inspired from and based on the `Werkzeug`_ project (c.f.
        ``werkzeug.datastructures.MultiDict``).

    """

    def __init__(self, mapping: 'Optional[dict[_KT, _VT] | Iterable[tuple[_KT, _VT]]]' = None) -> 'None':  # pylint: disable=line-too-long
        if isinstance(mapping, MultiDict):
            dict.__init__(self, ((k, v[:]) for k, v in mapping.items()))
        elif isinstance(mapping, dict):
            tmp = {}  # type: dict[_KT, list[_VT]]
            for key, value in mapping.items():
                if isinstance(value, (tuple, list)):
                    if len(value) == 0:
                        continue
                    value = list(value)
                else:
                    value = [value]
                tmp[key] = value
            dict.__init__(self, tmp)
        else:
            tmp = {}
            for key, value in mapping or ():
                tmp.setdefault(key, []).append(value)
            dict.__init__(self, tmp)

    def __getstate__(self) -> 'dict[_KT, list[_VT]]':
        return dict(self.lists())

    def __setstate__(self, value: 'Iterable[tuple[_KT, list[_VT]]]') -> 'None':
        dict.clear(self)
        dict.update(self, value)  # type: ignore[arg-type]

    def __iter__(self) -> 'Iterator[_KT]':
        return dict.__iter__(self)

    def __getitem__(self, key: '_KT') -> '_VT':
        """Return the first data value for this key.

        Args:
            key: The key to be looked up.

        Raises:
            KeyError: if the key does not exist.

        """
        if key in self:
            lst = dict.__getitem__(self, key)
            if len(lst) > 0:
                return lst[0]
        raise MissingKeyError(key, quiet=True)

    def __setitem__(self, key: '_KT', value: '_VT') -> 'None':
        """Like :meth:`add` but removes an existing key first.

        Args:
            key: The key for the value.
            value: The value to set.

        """
        dict.__setitem__(self, key, [value])

    def add(self, key: '_KT', value: '_VT') -> 'None':
        """Adds a new value for the key.

        Args:
            key: The key for the value.
            value: The value to add.

        """
        dict.setdefault(self, key, []).append(value)  # type: ignore[arg-type,attr-defined]

    @overload
    def get(self, key: '_KT') -> '_VT | _T': ...
    @overload
    def get(self, key: '_KT', default: '_VT | _T' = ...) -> '_VT | _T': ...

    def get(self, key: '_KT', default: '_VT | _T' = None) -> '_VT | _T':  # type: ignore[assignment,misc]
        try:
            return self[key]
        except MissingKeyError:
            return default

    def getlist(self, key: '_KT') -> 'list[_VT]':
        """Return the list of items for a given key.

        If that key is not in the :class:`MultiDict`, the return value
        will be an empty list.

        Args:
            key: The key to be looked up.

        Returns:
            A :obj:`list` of all the values for the key.

        """
        try:
            rv = dict.__getitem__(self, key)  # type: list[_VT]
        except KeyError:
            return []
        return list(rv)

    def setlist(self, key: '_KT', new_list: 'Iterable[_VT]') -> 'None':
        """Remove the old values for a key and add new ones.

        Notes:
            The list you pass the values in will be shallow-copied before it is
            inserted in the dictionary.

        Args:
            key: The key for which the values are set.
            new_list: An iterable with the new values for the key. Old values
                are removed first.

        """
        dict.__setitem__(self, key, list(new_list))

    def setdefault(self, key: '_KT', default: 'Optional[_VT]' = None) -> '_VT':
        """If key is in the dictionary, returns its value.

        If not, set it to default and return default.

        Args:
            key: The key to be looked up.
            default: The value to be set.

        Returns:
            The value of the key.

        """
        if key not in self:
            self[key] = cast('_VT', default)
        else:
            default = self[key]
        return default  # type: ignore[return-value]

    def setlistdefault(self, key: '_KT', default_list: 'Optional[Iterable[_VT]]' = None) -> 'list[_VT]':
        """Like :meth:`setdefault` but sets multiple values.

        The list returned is not a copy, but the list that is actually used
        internally. This means that you can put new values into the
        :class:`dict <MultiDict>` by appending items to the list.

        Args:
            key: The key to be looked up.
            default_list: An iterable of default values. It is either copied
                (in case it was a :obj:`list`) or converted into a :obj:`list`
                before returned.

        """
        if key not in self:
            default_list = list(default_list or ())
            dict.__setitem__(self, key, default_list)
        else:
            default_list = cast('list[_VT]', dict.__getitem__(self, key))
        return default_list

    def items(self, multi: 'bool' = False) -> 'Iterable[tuple[_KT, _VT]]':  # type: ignore[override]
        """Return an interator of ``(key, value)`` paris.

        Args:
            multi: If set to :obj:`True` the iterator returned will have a pair
                for each value of each key. Otherwise it will only contain
                pairs for the first value of each key.

        """
        for key, values in dict.items(self):
            if multi:
                for value in values:
                    yield key, value
            else:
                yield key, values[0]

    def lists(self) -> 'Iterator[tuple[_KT, list[_VT]]]':
        """Return an iterator of ``(key, values)`` pairs, where ``values`` is
        the :obj:`list` of all values associated with the key."""
        for key, values in dict.items(self):
            yield key, list(values)

    def values(self) -> 'Iterator[_VT]':  # type: ignore[override]
        """Returns an iterator of the first value on every key's value list."""
        for values in dict.values(self):
            yield values[0]

    def listvalues(self) -> 'Iterator[list[_VT]]':
        """Return an iterator of all values associated with a key. Zipping
        :meth:`keys` and this is the same as calling :meth:`lists`."""
        return dict.values(self)  # type: ignore[return-value]

    def copy(self) -> 'MultiDict[_KT, _VT]':
        """Return a shallow copy of this object."""
        return self.__class__(self)

    def deepcopy(self, memo: 'Optional[dict]' = None) -> 'MultiDict[_KT, _VT]':
        """Return a deep copy of this object."""
        return self.__class__(copy.deepcopy(self.to_dict(flat=False), memo=memo))  # type: ignore[arg-type]

    @overload
    def to_dict(self, flat: 'Literal[True]' = ...) -> 'dict[_KT, _VT]': ...
    @overload
    def to_dict(self, flat: 'Literal[False]') -> 'dict[_KT, list[_VT]]': ...

    def to_dict(self, flat: 'bool' = True) -> 'dict[_KT, _VT] | dict[_KT, list[_VT]]':
        """Return the contents as regular :obj:`dict`.

        If ``flat`` is :obj:`True` the returned :obj:`dict` will only have the
        first item present, if ``flat`` is :obj:`False` all values will be
        returned as lists.

        Args:
            flat: If set to :obj:`False` the :obj:`dict` returned will have
                lists with all the values in it. Otherwise it will only contain
                the first value for each key.

        """
        if flat:
            return dict(self.items())
        return dict(self.lists())

    def update(self, mapping: 'Mapping[_KT, _VT] | Iterable[tuple[_KT, _VT]]') -> 'None':  # type: ignore[override]
        """:meth:`update` extends rather than replaces existing key lists.

        If the value :obj:`list` for a key in ``other_dict`` is empty, no new
        values will be added to the :obj:`dict` and the key will not be
        created.

        Args:
            mapping: The extending value for the :class:`MultiDict`. Either a
                regular :obj:`dict`, an iterable of ``(key, value)`` tuples, or
                :obj:`None`.

        """
        for key, value in iter_multi_items(mapping):
            MultiDict.add(self, key, value)

    @overload
    def pop(self, key: '_KT') -> '_VT': ...
    @overload
    def pop(self, key: '_KT', default: '_VT | _T' = ...) -> '_VT | _T': ...

    def pop(self, key: '_KT', default: '_VT | _T' = _missing) -> '_VT | _T':  # type: ignore[assignment,misc]
        """Pop the first item for a :obj:`list` on the :obj:`dict`.

        Afterwards the ``key`` is removed from the :obj:`dict`, so additional
        values are discarded.

        Args:
            key: The key to pop.
            default: If provided the value to return if the key was not in the
                dictionary.

        """
        try:
            lst = dict.pop(self, key)

            if len(lst) == 0:
                raise MissingKeyError(key)

            return lst[0]
        except KeyError:
            if default is not _missing:
                return default

            raise MissingKeyError(key) from None

    def popitem(self) -> 'tuple[_KT, _VT]':
        """Pop an item from the :obj:`dict`."""
        try:
            item = dict.popitem(self)

            if len(item[1]) == 0:  # type: ignore[arg-type]
                raise MissingKeyError(item[0])

            return (item[0], item[1][0])  # type: ignore[index,return-value]
        except KeyError as e:
            raise MissingKeyError(e.args[0]) from None

    def poplist(self, key: '_KT') -> 'list[_VT]':
        """Pop the :obj:`list` for a key from the :obj:`dict`.

        If the key is not in the :obj:`dict` an empty :obj:`list` is returned.

        Notes:
            If the key does no longer exist a :obj:`list` is returned instead
            of raising an error.

        Args:
            key: The key to pop.

        """
        return dict.pop(self, key, [])

    def popitemlist(self) -> 'tuple[_KT, list[_VT]]':
        """Pop a ``(key, list)`` :obj:`tuple` from the :obj:`dict`."""
        try:
            return dict.popitem(self)  # type: ignore[return-value]
        except KeyError as e:
            raise MissingKeyError(e.args[0]) from None

    def __copy__(self) -> 'MultiDict[_KT, _VT]':
        return self.copy()

    def __deepcopy__(self, memo: 'Optional[dict]' = None) -> 'MultiDict[_KT, _VT]':
        return self.deepcopy(memo=memo)

    def __repr__(self) -> 'str':
        return f'{type(self).__name__}({list(self.items(multi=True))!r})'


class OrderedMultiDict(MultiDict[_KT, _VT]):
    """Works like a regular :class:`MultiDict` but preserves the order of the
    fields.

    Args:
        mapping: The initial value for the :class:`MultiDict`. Either a
            regular :obj:`dict`, an iterable of ``(key, value)`` tuples, or
            :obj:`None`.

    To convert the ordered multi dict into a :obj:`list` you can us the
    :meth:`items` method and pass it ``multi=True``.

    In general an :class:`OrderedMultiDict` is an order of magnitude slower
    than a :class:`MultiDict`.

    Notes:
        Due to a limitation in Python you cannot convert an ordered multi dict
        into a regular :obj:`dict` by using ``dict(multidict)``. Instead you
        have to use the :meth:`to_dict` method, otherwise the internal bucket
        objects are exposed.

    """
    _first_bucket: 'Optional[_omd_bucket[_KT, _VT]]'
    _last_bucket: 'Optional[_omd_bucket[_KT, _VT]]'

    def __init__(self, mapping: 'Optional[dict[_KT, _VT] | Iterable[tuple[_KT, _VT]]]' = None) -> 'None':  # pylint: disable=line-too-long
        dict.__init__(self)  # pylint: disable=non-parent-init-called
        self._first_bucket = self._last_bucket = None
        if mapping is not None:
            OrderedMultiDict.update(self, mapping)

    def __eq__(self, other: 'Any') -> 'bool':
        if not isinstance(other, MultiDict):
            return NotImplemented
        if isinstance(other, OrderedMultiDict):
            iter1 = iter(self.items(multi=True))
            iter2 = iter(other.items(multi=True))
            try:
                for k1, v1 in iter1:
                    k2, v2 = next(iter2)
                    if k1 != k2 or v1 != v2:
                        return False
            except StopIteration:
                return False
            try:
                next(iter2)
            except StopIteration:
                return True
            return False
        if len(self) != len(other):
            return False
        for key, values in self.lists():
            if other.getlist(key) != values:
                return False
        return True

    __hash__ = None  # type: ignore[assignment]

    def __reduce_ex__(self, protocol: 'SupportsIndex') -> 'tuple[type, tuple[list[tuple[_KT, _VT]]]]':
        return type(self), (list(self.items(multi=True)),)

    def __getstate__(self) -> 'list[tuple[_KT, _VT]]':  # type: ignore[override]
        return list(self.items(multi=True))

    def __setstate__(self, values: 'Iterable[tuple[_KT, _VT]]') -> 'None':  # type: ignore[override]
        dict.clear(self)
        for key, value in values:
            self.add(key, value)

    def __getitem__(self, key: '_KT') -> '_VT':
        if key in self:
            return dict.__getitem__(self, key)[0].value
        raise MissingKeyError(key, quiet=True)

    def __setitem__(self, key: '_KT', value: '_VT') -> 'None':
        self.poplist(key)
        self.add(key, value)

    def __delitem__(self, key: '_KT') -> 'None':
        self.pop(key)

    def keys(self) -> 'Iterator[_KT]':  # type: ignore[override]
        return (key for key, _ in self.items())

    def __iter__(self) -> 'Iterator[_KT]':
        return iter(self.keys())

    def values(self) -> 'Iterator[_VT]':  # type: ignore[override]
        return (value for _, value in self.items())

    def items(self, multi: 'bool' = False) -> 'Iterator[tuple[_KT, _VT]]':  # type: ignore[override]
        ptr = self._first_bucket
        if multi:
            while ptr is not None:
                yield ptr.key, ptr.value
                ptr = ptr.next
        else:
            returned_keys = set()  # type: 'set[_KT]'
            while ptr is not None:
                if ptr.key not in returned_keys:
                    returned_keys.add(ptr.key)
                    yield ptr.key, ptr.value
                ptr = ptr.next

    def lists(self) -> 'Iterator[tuple[_KT, list[_VT]]]':
        returned_keys = set()  # type: 'set[_KT]'
        ptr = self._first_bucket
        while ptr is not None:
            if ptr.key not in returned_keys:
                yield ptr.key, self.getlist(ptr.key)
                returned_keys.add(ptr.key)
            ptr = ptr.next

    def listvalues(self) -> 'Iterator[list[_VT]]':
        for _, values in self.lists():
            yield values

    def add(self, key: '_KT', value: '_VT') -> 'None':
        dict.setdefault(self, key, []).append(_omd_bucket(self, key, value))  # type: ignore[arg-type,attr-defined]

    def getlist(self, key: '_KT') -> 'list[_VT]':
        try:
            rv = dict.__getitem__(self, key)
        except KeyError:
            return []
        return [x.value for x in rv]

    def setlist(self, key: '_KT', new_list: 'Iterable[_VT]') -> 'None':
        self.poplist(key)
        for value in new_list:
            self.add(key, value)

    def setlistdefault(self, key: '_KT', default_list: 'Optional[Iterable[_VT]]' = None) -> 'NoReturn':
        raise UnsupportedCall('setlistdefault is unsupported for ordered multi dicts')

    def update(self, mapping: 'Mapping[_KT, _VT] | Iterable[tuple[_KT, _VT]]') -> 'None':  # type: ignore[override]
        for key, value in iter_multi_items(mapping):
            OrderedMultiDict.add(self, key, value)

    def poplist(self, key: '_KT') -> 'list[_VT]':
        buckets = dict.pop(self, key, [])  # type: list[_omd_bucket[_KT, _VT]]
        for bucket in buckets:
            bucket.unlink(self)
        return [x.value for x in buckets]

    @overload
    def pop(self, key: '_KT') -> '_VT': ...
    @overload
    def pop(self, key: '_KT', default: '_VT | _T' = ...) -> '_VT | _T': ...

    def pop(self, key: '_KT', default: '_VT | _T' = _missing) -> '_VT | _T':  # type: ignore[assignment,misc]
        try:
            buckets = dict.pop(self, key)  # type: list[_omd_bucket[_KT, _VT]]
        except KeyError:
            if default is not _missing:
                return default

            raise MissingKeyError(key) from None

        for bucket in buckets:
            bucket.unlink(self)

        return buckets[0].value

    def popitem(self) -> 'tuple[_KT, _VT]':
        try:
            key, buckets = cast('tuple[_KT, list[_omd_bucket[_KT, _VT]]]', dict.popitem(self))
        except KeyError as e:
            raise MissingKeyError(str(e)) from None

        for bucket in buckets:
            bucket.unlink(self)

        return key, buckets[0].value

    def popitemlist(self) -> 'tuple[_KT, list[_VT]]':
        try:
            key, buckets = cast('tuple[_KT, list[_omd_bucket[_KT, _VT]]]', dict.popitem(self))
        except KeyError as e:
            raise MissingKeyError(str(e)) from None

        for bucket in buckets:
            bucket.unlink(self)

        return key, [x.value for x in buckets]
