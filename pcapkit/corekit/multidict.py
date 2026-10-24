# -*- coding: utf-8 -*-
"""Multi-Mapping Dictionary
==============================

.. module:: pcapkit.corekit.multidict

:mod:`pcapkit.corekit.multidict` contains multi-mapping dictionary classes,
which are used to store multiple mappings of the same key. The implementation
is ported from `Werkzeug`_ 3.1.9, ``werkzeug/datastructures/structures.py``.

"""

import collections.abc as cabc
import copy
from typing import TYPE_CHECKING, Generic, TypeVar, overload

from pcapkit.utilities.exceptions import MissingKeyError, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, Mapping, NoReturn, Optional, SupportsIndex

    from typing_extensions import Literal, Self

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
    """Wraps values in the :class:`OrderedMultiDict`.  This makes it
    possible to keep an order over multiple different keys.  It requires
    a lot of extra memory and slows down access a lot, but makes it
    possible to access elements in O(1) and iterate in O(n).
    """

    __slots__ = ("prev", "key", "value", "next")

    def __init__(self, omd: 'OrderedMultiDict[_KT, _VT]', key: '_KT', value: '_VT') -> 'None':
        self.prev: 'Optional[_omd_bucket[_KT, _VT]]' = omd._last_bucket
        self.key: '_KT' = key
        self.value: '_VT' = value
        self.next: 'Optional[_omd_bucket[_KT, _VT]]' = None

        if omd._first_bucket is None:
            omd._first_bucket = self
        if omd._last_bucket is not None:
            omd._last_bucket.next = self
        omd._last_bucket = self

    def unlink(self, omd: 'OrderedMultiDict[_KT, _VT]') -> 'None':
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


def iter_multi_items(mapping: 'MultiDict[_KT, _VT] | Mapping[_KT, _VT | list[_VT] | tuple[_VT, ...] | set[_VT]] | Iterable[tuple[_KT, _VT]]') -> 'Iterator[tuple[_KT, _VT]]':  # pylint: disable=line-too-long
    """Iterates over the items of a mapping yielding keys and values
    without dropping any from more complex structures.
    """
    if isinstance(mapping, MultiDict):
        yield from mapping.items(multi=True)
    elif isinstance(mapping, cabc.Mapping):
        for key, value in mapping.items():
            if isinstance(value, (list, tuple, set)):
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
    multiple values for the same key which is for example used by the parsing
    functions in the wrappers.  This is necessary because some HTML form
    elements pass multiple values for the same key.

    :class:`MultiDict` implements all standard dictionary methods.
    Internally, it saves all values for a key as a list, but the standard dict
    access methods will only return the first value for a key. If you want to
    gain access to the other values, too, you have to use the `list` methods as
    explained below.

    Basic Usage:

    >>> d = MultiDict([('a', 'b'), ('a', 'c')])
    >>> d
    MultiDict([('a', 'b'), ('a', 'c')])
    >>> d['a']
    'b'
    >>> d.getlist('a')
    ['b', 'c']
    >>> 'a' in d
    True

    It behaves like a normal dict thus all dict functions will only return the
    first value when multiple values for one key are found.

    A :class:`MultiDict` can be constructed from an iterable of
    ``(key, value)`` tuples, a dict, a :class:`MultiDict` or from Werkzeug 0.2
    onwards some keyword parameters.

    :param mapping: the initial value for the :class:`MultiDict`.  Either a
                    regular dict, an iterable of ``(key, value)`` tuples
                    or `None`.
    """

    def __init__(self, mapping: 'Optional[MultiDict[_KT, _VT] | Mapping[_KT, _VT | list[_VT] | tuple[_VT, ...] | set[_VT]] | Iterable[tuple[_KT, _VT]]]' = None) -> 'None':  # pylint: disable=line-too-long
        if mapping is None:
            super().__init__()
        elif isinstance(mapping, MultiDict):
            # NOTE: a dict, not pairs: GraalPy's dict.__init__ stores pairs
            # through __setitem__, wrapping each list in another (#1963).
            super().__init__({k: vs[:] for k, vs in mapping.lists()})
        elif isinstance(mapping, cabc.Mapping):
            tmp = {}  # type: dict[_KT, list[_VT]]
            for key, value in mapping.items():
                if isinstance(value, (list, tuple, set)):
                    value = list(value)

                    if not value:
                        continue
                else:
                    value = [value]
                tmp[key] = value
            super().__init__(tmp)
        else:
            tmp = {}
            for key, value in mapping:  # type: ignore[misc]
                tmp.setdefault(key, []).append(value)
            super().__init__(tmp)

    def __getstate__(self) -> 'Any':
        return dict(self.lists())

    def __setstate__(self, value: 'Any') -> 'None':
        super().clear()
        # NOTE: a dict, not pairs, as in __init__ (GraalPy, #1963).
        super().update(dict(value))

    def __iter__(self) -> 'Iterator[_KT]':  # pylint: disable=useless-parent-delegation
        # https://github.com/python/cpython/issues/87412
        # If __iter__ is not overridden, Python uses a fast path for dict(md),
        # taking the data directly and getting lists of values, rather than
        # calling __getitem__ and getting only the first value.
        return super().__iter__()

    def __getitem__(self, key: '_KT') -> '_VT':
        """Return the first data value for this key;
        raises KeyError if not found.

        :param key: The key to be looked up.
        :raise KeyError: if the key does not exist.
        """

        if key in self:
            lst = super().__getitem__(key)
            if len(lst) > 0:
                return lst[0]
        raise MissingKeyError(key, quiet=True)

    def __setitem__(self, key: '_KT', value: '_VT') -> 'None':
        """Like :meth:`add` but removes an existing key first.

        :param key: the key for the value.
        :param value: the value to set.
        """
        super().__setitem__(key, [value])

    def add(self, key: '_KT', value: '_VT') -> 'None':
        """Adds a new value for the key.

        :param key: the key for the value.
        :param value: the value to add.
        """
        super().setdefault(key, []).append(value)

    @overload
    def get(self, key: '_KT') -> '_VT | _T': ...
    @overload
    def get(self, key: '_KT', default: '_VT | _T' = ...) -> '_VT | _T': ...

    def get(self, key: '_KT', default: '_VT | _T' = None) -> '_VT | _T':  # type: ignore[assignment]
        try:
            return self[key]
        except MissingKeyError:
            return default

    def getlist(self, key: '_KT') -> 'list[_VT]':
        """Return the list of items for a given key. If that key is not in the
        `MultiDict`, the return value will be an empty list.

        :param key: The key to be looked up.
        :return: a :class:`list` of all the values for the key.
        """
        try:
            rv = super().__getitem__(key)  # type: list[_VT]
        except KeyError:
            return []
        return list(rv)

    def setlist(self, key: '_KT', new_list: 'Iterable[_VT]') -> 'None':
        """Remove the old values for a key and add new ones.  Note that the list
        you pass the values in will be shallow-copied before it is inserted in
        the dictionary.

        >>> d = MultiDict()
        >>> d.setlist('foo', ['1', '2'])
        >>> d['foo']
        '1'
        >>> d.getlist('foo')
        ['1', '2']

        :param key: The key for which the values are set.
        :param new_list: An iterable with the new values for the key.  Old values
                         are removed first.
        """
        super().__setitem__(key, list(new_list))

    @overload  # type: ignore[override]
    def setdefault(self, key: '_KT') -> 'None': ...
    @overload
    def setdefault(self, key: '_KT', default: '_VT') -> '_VT': ...

    def setdefault(self, key: '_KT', default: 'Optional[_VT]' = None) -> 'Optional[_VT]':
        """Returns the value for the key if it is in the dict, otherwise it
        returns `default` and sets that value for `key`.

        :param key: The key to be looked up.
        :param default: The default value to be returned if the key is not
                        in the dict.  If not further specified it's `None`.
        """
        if key not in self:
            self[key] = default  # type: ignore[assignment]

        return self[key]

    def setlistdefault(self, key: '_KT', default_list: 'Optional[Iterable[_VT]]' = None) -> 'list[_VT]':
        """Like `setdefault` but sets multiple values.  The list returned
        is not a copy, but the list that is actually used internally.  This
        means that you can put new values into the dict by appending items
        to the list:

        >>> d = MultiDict({"foo": 1})
        >>> d.setlistdefault("foo").extend([2, 3])
        >>> d.getlist("foo")
        [1, 2, 3]

        :param key: The key to be looked up.
        :param default_list: An iterable of default values.  It is either copied
                             (in case it was a list) or converted into a list
                             before returned.
        :return: a :class:`list`
        """
        if key not in self:
            super().__setitem__(key, list(default_list or ()))

        return super().__getitem__(key)

    def items(self, multi: 'bool' = False) -> 'Iterable[tuple[_KT, _VT]]':  # type: ignore[override]
        """Return an iterator of ``(key, value)`` pairs.

        :param multi: If set to `True` the iterator returned will have a pair
                      for each value of each key.  Otherwise it will only
                      contain pairs for the first value of each key.
        """
        values: 'list[_VT]'

        for key, values in super().items():
            if multi:
                for value in values:
                    yield key, value
            else:
                yield key, values[0]

    def lists(self) -> 'Iterable[tuple[_KT, list[_VT]]]':
        """Return a iterator of ``(key, values)`` pairs, where values is the list
        of all values associated with the key."""
        values: 'list[_VT]'

        for key, values in super().items():
            yield key, list(values)

    def values(self) -> 'Iterable[_VT]':  # type: ignore[override]
        """Returns an iterator of the first value on every key's value list."""
        values: 'list[_VT]'

        for values in super().values():
            yield values[0]

    def listvalues(self) -> 'Iterable[list[_VT]]':
        """Return an iterator of all values associated with a key.  Zipping
        :meth:`keys` and this is the same as calling :meth:`lists`:

        >>> d = MultiDict({"foo": [1, 2, 3]})
        >>> zip(d.keys(), d.listvalues()) == d.lists()
        True
        """
        return super().values()

    def copy(self) -> 'Self':
        """Return a shallow copy of this object."""
        return self.__class__(self)

    def deepcopy(self, memo: 'Any' = None) -> 'Self':
        """Return a deep copy of this object."""
        return self.__class__(copy.deepcopy(self.to_dict(flat=False), memo))

    @overload
    def to_dict(self, flat: 'Literal[True]' = ...) -> 'dict[_KT, _VT]': ...
    @overload
    def to_dict(self, flat: 'Literal[False]') -> 'dict[_KT, list[_VT]]': ...

    def to_dict(self, flat: 'bool' = True) -> 'dict[_KT, _VT] | dict[_KT, list[_VT]]':
        """Return the contents as regular dict.  If `flat` is `True` the
        returned dict will only have the first item present, if `flat` is
        `False` all values will be returned as lists.

        :param flat: If set to `False` the dict returned will have lists
                     with all the values in it.  Otherwise it will only
                     contain the first value for each key.
        :return: a :class:`dict`
        """
        if flat:
            return dict(self.items())
        return dict(self.lists())

    def update(self, mapping: 'MultiDict[_KT, _VT] | Mapping[_KT, _VT | list[_VT] | tuple[_VT, ...] | set[_VT]] | Iterable[tuple[_KT, _VT]]') -> 'None':  # type: ignore[override] # pylint: disable=line-too-long
        """update() extends rather than replaces existing key lists:

        >>> a = MultiDict({'x': 1})
        >>> b = MultiDict({'x': 2, 'y': 3})
        >>> a.update(b)
        >>> a
        MultiDict([('y', 3), ('x', 1), ('x', 2)])

        If the value list for a key in ``other_dict`` is empty, no new values
        will be added to the dict and the key will not be created:

        >>> x = {'empty_list': []}
        >>> y = MultiDict()
        >>> y.update(x)
        >>> y
        MultiDict([])
        """
        for key, value in iter_multi_items(mapping):
            self.add(key, value)

    def __or__(self, other: 'Mapping[_KT, _VT | list[_VT] | tuple[_VT, ...] | set[_VT]]') -> 'MultiDict[_KT, _VT]':  # type: ignore[override] # pylint: disable=line-too-long
        if not isinstance(other, cabc.Mapping):
            return NotImplemented

        rv = self.copy()
        rv.update(other)
        return rv

    def __ior__(self, other: 'Mapping[_KT, _VT | list[_VT] | tuple[_VT, ...] | set[_VT]] | Iterable[tuple[_KT, _VT]]') -> 'Self':  # type: ignore[override] # pylint: disable=line-too-long
        if not isinstance(other, (cabc.Mapping, cabc.Iterable)):
            return NotImplemented

        self.update(other)
        return self

    @overload
    def pop(self, key: '_KT') -> '_VT': ...
    @overload
    def pop(self, key: '_KT', default: '_VT') -> '_VT': ...  # pylint: disable=arguments-differ
    @overload
    def pop(self, key: '_KT', default: '_T') -> '_VT | _T': ...  # pylint: disable=arguments-differ

    def pop(self, key: '_KT', default: '_VT | _T' = _missing) -> '_VT | _T':  # type: ignore[assignment]
        """Pop the first item for a list on the dict.  Afterwards the
        key is removed from the dict, so additional values are discarded:

        >>> d = MultiDict({"foo": [1, 2, 3]})
        >>> d.pop("foo")
        1
        >>> "foo" in d
        False

        :param key: the key to pop.
        :param default: if provided the value to return if the key was
                        not in the dictionary.
        """
        lst: 'list[_VT]'

        try:
            lst = super().pop(key)

            if len(lst) == 0:
                raise MissingKeyError(key)

            return lst[0]
        except KeyError:
            if default is not _missing:
                return default

            raise MissingKeyError(key) from None

    def popitem(self) -> 'tuple[_KT, _VT]':
        """Pop an item from the dict."""
        item: 'tuple[_KT, list[_VT]]'

        try:
            item = super().popitem()

            if len(item[1]) == 0:
                raise MissingKeyError(item[0])

            return item[0], item[1][0]
        except KeyError as e:
            raise MissingKeyError(e.args[0]) from None

    def poplist(self, key: '_KT') -> 'list[_VT]':
        """Pop the list for a key from the dict.  If the key is not in the dict
        an empty list is returned.
        """
        return super().pop(key, [])

    def popitemlist(self) -> 'tuple[_KT, list[_VT]]':
        """Pop a ``(key, list)`` tuple from the dict."""
        try:
            return super().popitem()
        except KeyError as e:
            raise MissingKeyError(e.args[0]) from None

    def __copy__(self) -> 'Self':
        return self.copy()

    def __deepcopy__(self, memo: 'Any') -> 'Self':
        return self.deepcopy(memo=memo)

    def __repr__(self) -> 'str':
        return f"{type(self).__name__}({list(self.items(multi=True))!r})"


class OrderedMultiDict(MultiDict[_KT, _VT]):
    """Works like a regular :class:`MultiDict` but preserves the
    order of the fields.  To convert the ordered multi dict into a
    list you can use the :meth:`items` method and pass it ``multi=True``.

    In general an :class:`OrderedMultiDict` is an order of magnitude
    slower than a :class:`MultiDict`.

    .. admonition:: note

       Due to a limitation in Python you cannot convert an ordered
       multi dict into a regular dict by using ``dict(multidict)``.
       Instead you have to use the :meth:`to_dict` method, otherwise
       the internal bucket objects are exposed.
    """

    def __init__(self, mapping: 'Optional[MultiDict[_KT, _VT] | Mapping[_KT, _VT | list[_VT] | tuple[_VT, ...] | set[_VT]] | Iterable[tuple[_KT, _VT]]]' = None) -> 'None':  # pylint: disable=line-too-long
        super().__init__()
        self._first_bucket: 'Optional[_omd_bucket[_KT, _VT]]' = None
        self._last_bucket: 'Optional[_omd_bucket[_KT, _VT]]' = None
        if mapping is not None:
            self.update(mapping)

    def __eq__(self, other: 'object') -> 'bool':
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

    def deepcopy(self, memo: 'Optional[dict]' = None) -> 'OrderedMultiDict[_KT, _VT]':
        """Return a deep copy of this object.

        Notes:
            :meth:`MultiDict.deepcopy` rebuilds from :meth:`to_dict` with
            ``flat=False``, which groups the values by key. This rebuilds from
            ``items(multi=True)`` instead, so the copy keeps the insertion
            order of interleaved keys. :meth:`__deepcopy__` reaches it too.

        .. versionchanged:: 1.5.0

           Keeps the insertion order of interleaved keys, where the copy grouped
           the values by key (:issue:`1295`).

        """
        return self.__class__(copy.deepcopy(list(self.items(multi=True)), memo=memo))

    def __reduce_ex__(self, protocol: 'SupportsIndex') -> 'Any':
        return type(self), (list(self.items(multi=True)),)

    def __getstate__(self) -> 'Any':
        return list(self.items(multi=True))

    def __setstate__(self, values: 'Any') -> 'None':
        self.clear()

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

    def keys(self) -> 'Iterable[_KT]':  # type: ignore[override]
        return (key for key, _ in self.items())

    def __iter__(self) -> 'Iterator[_KT]':
        return iter(self.keys())

    def values(self) -> 'Iterable[_VT]':  # type: ignore[override]
        return (value for key, value in self.items())

    def items(self, multi: 'bool' = False) -> 'Iterable[tuple[_KT, _VT]]':  # type: ignore[override]
        ptr = self._first_bucket
        if multi:
            while ptr is not None:
                yield ptr.key, ptr.value
                ptr = ptr.next
        else:
            returned_keys = set()
            while ptr is not None:
                if ptr.key not in returned_keys:
                    returned_keys.add(ptr.key)
                    yield ptr.key, ptr.value
                ptr = ptr.next

    def lists(self) -> 'Iterable[tuple[_KT, list[_VT]]]':
        returned_keys = set()
        ptr = self._first_bucket
        while ptr is not None:
            if ptr.key not in returned_keys:
                yield ptr.key, self.getlist(ptr.key)
                returned_keys.add(ptr.key)
            ptr = ptr.next

    def listvalues(self) -> 'Iterable[list[_VT]]':
        for _key, values in self.lists():
            yield values

    def add(self, key: '_KT', value: '_VT') -> 'None':
        dict.setdefault(self, key, []).append(_omd_bucket(self, key, value))

    def getlist(self, key: '_KT') -> 'list[_VT]':
        rv: 'list[_omd_bucket[_KT, _VT]]'

        try:
            rv = dict.__getitem__(self, key)
        except KeyError:
            return []
        return [x.value for x in rv]

    def setlist(self, key: '_KT', new_list: 'Iterable[_VT]') -> 'None':
        self.poplist(key)
        for value in new_list:
            self.add(key, value)

    def setlistdefault(self, key: 'Any', default_list: 'Any' = None) -> 'NoReturn':
        raise UnsupportedCall("setlistdefault is unsupported for ordered multi dicts")

    def update(self, mapping: 'MultiDict[_KT, _VT] | Mapping[_KT, _VT | list[_VT] | tuple[_VT, ...] | set[_VT]] | Iterable[tuple[_KT, _VT]]') -> 'None':  # type: ignore[override] # pylint: disable=line-too-long
        for key, value in iter_multi_items(mapping):
            self.add(key, value)

    def poplist(self, key: '_KT') -> 'list[_VT]':
        buckets: 'Iterable[_omd_bucket[_KT, _VT]]' = dict.pop(self, key, [])
        for bucket in buckets:
            bucket.unlink(self)
        return [x.value for x in buckets]

    @overload
    def pop(self, key: '_KT') -> '_VT': ...
    @overload
    def pop(self, key: '_KT', default: '_VT') -> '_VT': ...  # pylint: disable=arguments-differ
    @overload
    def pop(self, key: '_KT', default: '_T') -> '_VT | _T': ...  # pylint: disable=arguments-differ

    def pop(self, key: '_KT', default: '_VT | _T' = _missing) -> '_VT | _T':  # type: ignore[assignment]
        buckets: 'list[_omd_bucket[_KT, _VT]]'

        try:
            buckets = dict.pop(self, key)
        except KeyError:
            if default is not _missing:
                return default

            raise MissingKeyError(key) from None

        for bucket in buckets:
            bucket.unlink(self)

        return buckets[0].value

    def popitem(self) -> 'tuple[_KT, _VT]':
        key: '_KT'
        buckets: 'list[_omd_bucket[_KT, _VT]]'

        try:
            key, buckets = dict.popitem(self)
        except KeyError as e:
            raise MissingKeyError(e.args[0]) from None

        for bucket in buckets:
            bucket.unlink(self)

        return key, buckets[0].value

    def popitemlist(self) -> 'tuple[_KT, list[_VT]]':
        key: '_KT'
        buckets: 'list[_omd_bucket[_KT, _VT]]'

        try:
            key, buckets = dict.popitem(self)
        except KeyError as e:
            raise MissingKeyError(e.args[0]) from None

        for bucket in buckets:
            bucket.unlink(self)

        return key, [x.value for x in buckets]
