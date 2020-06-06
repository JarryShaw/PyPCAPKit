# -*- coding: utf-8 -*-
"""info class

:mod:`pcapkit.corekit.infoclass` contains :obj:`dict` like class
:class:`~pcapkit.corekit.infoclass.Info` only, which is originally
designed to work alike :func:`dataclasses.dataclass` as introduced
in :pep:`557`.

"""
import collections.abc
import copy

from pcapkit.utilities.exceptions import UnsupportedCall
from pcapkit.utilities.validations import dict_check

__all__ = ['Info']


class Info(collections.abc.Mapping):
    """Turn dictionaries into :obj:`object` like instances.

    Notes:
        * :class:`Info` objects inherit from :obj:`dict` type
        * :class:`Info` objects are *iterable*, and support all functions as :obj:`dict`
        * :class:`Info` objects are **one-time-modeling**, thus cannot set or delete
          attributes after initialisation

    """

    def __new__(cls, dict_=None, **kwargs):
        """Create a new instance.

        Args:
            dict_ (Dict[str, Any]): Source :obj:`dict` data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Notes:
            Keys with the same names as the builtin methods will be renamed
            with ``2`` suffix implicitly and internally.

        """
        def __read__(dict_):
            __dict__ = dict()
            for (key, value) in dict_.items():
                if key in self.__data__:
                    key = f'{key}2'
                if isinstance(value, dict):
                    __dict__[key] = Info(value)
                else:
                    # if isinstance(key, str):
                    #     key = re.sub(r'\W', '_', key)
                    __dict__[key] = value
            return __dict__

        temp = list()
        for obj in cls.mro():
            temp.extend(dir(obj))
        cls.__data__ = set(temp)

        self = super().__new__(cls)
        if dict_ is not None:
            if isinstance(dict_, Info):
                self = copy.deepcopy(dict_)
            else:
                dict_check(dict_)
                self.__dict__.update(__read__(dict_))

        self.__dict__.update(__read__(kwargs))
        return self

    def __str__(self):
        temp = list()
        for (key, value) in self.__dict__.items():
            temp.append(f'{key}={value}')
        args = ', '.join(temp)
        return f'Info({args})'

    def __repr__(self):
        temp = list()
        for (key, value) in self.__dict__.items():
            if isinstance(value, Info):
                temp.append(f'{key}=Info(...)')
            else:
                temp.append(f'{key}={value!r}')
        args = ', '.join(temp)
        return f"Info({args})"

    def __len__(self):
        return len(self.__dict__)

    def __iter__(self):
        return iter(self.__dict__)

    def __getitem__(self, key):
        if key in self.__data__:
            key = f'{key}2'
        value = self.__dict__[key]
        if isinstance(value, (dict, collections.abc.Mapping)):
            return Info(value)
        return value

    def __setattr__(self, name, value):
        raise UnsupportedCall("can't set attribute")

    def __delattr__(self, name):
        raise UnsupportedCall("can't delete attribute")

    def info2dict(self):
        """Convert :class:`Info` into :obj:`dict`.

        Returns:
            Dict[str, Any]: Converted :obj:`dict`.

        """
        dict_ = dict()
        for (key, value) in self.__dict__.items():
            if isinstance(value, Info):
                dict_[key] = value.info2dict()
            elif isinstance(value, (tuple, list, set, frozenset)):
                temp = list()
                for item in value:
                    if isinstance(item, Info):
                        temp.append(item.info2dict())
                    else:
                        temp.append(item)
                dict_[key] = value.__class__(temp)
            else:
                dict_[key] = value
        return dict_
