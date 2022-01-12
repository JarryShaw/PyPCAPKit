# -*- coding: utf-8 -*-
"""info class

:mod:`pcapkit.corekit.infoclass` contains :obj:`dict` like class
:class:`~pcapkit.corekit.infoclass.Info` only, which is originally
designed to work alike :func:`dataclasses.dataclass` as introduced
in :pep:`557`.

"""
import collections.abc
import itertools
from typing import TYPE_CHECKING

from pcapkit.utilities.exceptions import KeyExists, UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, Mapping, NoReturn, Optional

__all__ = ['Info']


class Info(collections.abc.Mapping):
    """Turn dictionaries into :obj:`object` like instances.

    * :class:`Info` objects inherit from :obj:`dict` type
    * :class:`Info` objects are *iterable*, and support all functions as
      :obj:`dict` type
    * :class:`Info` objects are **immutable**, thus cannot set or delete
      attributes after initialisation

    Important:
        :class:`Info` will attempt to rename keys with the same names as the
        class's builtin methods, and store the mapping information in the
        :attr:`__map__` and :attr:`__map_reverse__` attributes. However, when
        accessing such renamed keys, the original key name should always be
        used, i.e., such renaming is totally transparent to the user.

    """

    __slots__ = ()

    #: Mapping of name conflicts with builtin methods (original names to
    #: transformed names).
    __map__: 'dict[str, str]'
    #: Mapping of name conflicts with builtin methods (transformed names to
    #: original names).
    __map_reverse__: 'dict[str, str]'
    #： List of builtin methods.
    __builtin__: 'set[str]'

    def __new__(cls, dict_: 'Optional[dict[str, Any]]' = None, **kwargs: 'Any') -> 'Info':
        """Create a new instance.

        Args:
            dict_: Source :obj:`dict` data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Notes:
            Keys with the same names as the class's builtin methods will be
            renamed with the class name prefixed as mangled class variables
            implicitly and internally. Such mapping information will be stored
            within :attr:`__map__` attribute.

        """
        cls.__map__ = {}

        temp = []  # type: list[str]
        for obj in cls.mro():
            temp.extend(dir(obj))
        cls.__builtin__ = set(temp)

        self = super().__new__(cls)
        if dict_ is not None:
            self.__update__(dict_)

        self.__update__(kwargs)
        return self

    def __update__(self, dict_: 'Optional[Mapping[str, Any] | Iterable[tuple[str, Any]]]' = None,
                   **kwargs: 'Any') -> 'None':
        __name__ = type(self).__name__  # pylint: disable=redefined-builtin

        if dict_ is None:
            data_iter = kwargs.items()  # type: Iterable[tuple[str, Any]] # pylint: disable=dict-items-not-iterating
        elif isinstance(dict_, collections.abc.Mapping):
            data_iter = itertools.chain(dict_.items(), kwargs.items())  # pylint: disable=dict-items-not-iterating
        else:
            data_iter = itertools.chain(dict_, kwargs.items())  # pylint: disable=dict-items-not-iterating

        for (key, value) in data_iter:
            if key in self.__builtin__:
                new_key = f'_{__name__}{key}'

                # NOTE: We keep record of the mapping bidirectionally.
                self.__map__[key] = new_key
                self.__map_reverse__[new_key] = key

                key = new_key

            if key in self.__dict__:
                raise KeyExists(f'{key} already exists')

            if isinstance(value, dict):
                self.__dict__[key] = Info(value)
            else:
                # NOTE: We don't rewrite the key names here, just keep the
                # original ones, even though they might break on the ``.``
                # (:obj:`getattr`) operator.

                # if isinstance(key, str):
                #     key = re.sub(r'\W', '_', key)
                self.__dict__[key] = value

    def __str__(self) -> 'str':
        temp = []  # type: list[str]
        for (key, value) in self.__dict__.items():
            out_key = self.__map_reverse__.get(key, key)
            temp.append(f'{out_key}={value}')
        args = ', '.join(temp)
        return f'{type(self).__name__}({args})'

    def __repr__(self) -> 'str':
        temp = []  # type: list[str]
        for (key, value) in self.__dict__.items():
            out_key = self.__map_reverse__.get(key, key)
            if isinstance(value, Info):
                temp.append(f'{out_key}={type(value).__name__}(...)')
            else:
                temp.append(f'{out_key}={value!r}')
        args = ', '.join(temp)
        return f'{type(self).__name__}({args})'

    def __len__(self) -> 'int':
        return len(self.__dict__)

    def __iter__(self) -> 'Iterator[str]':
        for key in self.__dict__:
            yield self.__map_reverse__.get(key, key)

    def __getitem__(self, key: 'str') -> 'Any':
        key = self.__map__.get(key, key)
        return self.__dict__[key]

    def __setattr__(self, name: 'str', value: 'Any') -> 'NoReturn':
        raise UnsupportedCall("can't set attribute")

    def __delattr__(self, name: 'str') -> 'NoReturn':
        raise UnsupportedCall("can't delete attribute")

    def info2dict(self) -> 'dict[str, Any]':
        """Convert :class:`Info` into :obj:`dict`.

        Important:
            We only convert nested :class:`Info` objects into :obj:`dict` if
            they are the direct value of the :class:`Info` object's attribute.
            Should such :class:`Info` objects be nested within other data,
            types, such as :obj:`list`, :obj:`tuple`, :obj:`set`, etc., we
            shall not convert them into :obj:`dict` and remain them intact.

        """
        dict_ = {}  # type: dict[str, Any]
        for (key, value) in self.__dict__.items():
            out_key = self.__map_reverse__.get(key, key)
            if isinstance(value, Info):
                dict_[out_key] = value.info2dict()

            #elif isinstance(value, (tuple, list, set, frozenset)):
            #    temp = []  # type: list[Any]
            #    for item in value:
            #        if isinstance(item, Info):
            #            temp.append(item.info2dict())
            #        else:
            #            temp.append(item)
            #    dict_[out_key] = value.__class__(temp)

            else:
                dict_[out_key] = value
        return dict_
