# -*- coding: utf-8 -*-
"""info class

`pcapkit.corekit.infoclass` contains dict-like class
`Info` only, which is originally designed to work alike
`dataclasses.dataclass` in Python 3.7 and later versions.

"""
import collections.abc
import copy

from pcapkit.utilities.exceptions import UnsupportedCall
from pcapkit.utilities.validations import dict_check

__all__ = ['Info']


class Info(collections.abc.Mapping):
    """Turn dictionaries into object-like instances.

    Methods:
        * info2dict -- reverse Info object into dict type

    Notes:
        * Info objects inherit from `dict` type
        * Info objects are iterable, and support all functions as `dict`
        * Info objects are one-time-modeling, thus cannot set or delete
            attributes after initialisation

    """
    def __new__(cls, dict_=None, **kwargs):
        def __read__(dict_):
            __dict__ = dict()
            for (key, value) in dict_.items():
                if key in self.__data__:
                    key = '{}2'.format(key)
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
            temp.append('{}={}'.format(key, value))
        args = ', '.join(temp)
        return 'Info({})'.format(args)

    def __repr__(self):
        temp = list()
        flag = False
        for (key, value) in self.__dict__.items():
            if isinstance(value, Info):
                flag = True
                continue
            temp.append('{}={!r}'.format(key, value))
        args = ', '.join(temp)
        return "Info({}{})".format(args, ', Info=(...)' if flag else '')

    def __len__(self):
        return len(self.__dict__)

    def __iter__(self):
        return iter(self.__dict__)

    def __getitem__(self, key):
        if key in self.__data__:
            key = '{}2'.format(key)
        value = self.__dict__[key]
        if isinstance(value, (dict, collections.abc.Mapping)):
            return Info(value)
        return value

    def __setattr__(self, name, value):
        raise UnsupportedCall("can't set attribute")

    def __delattr__(self, name):
        raise UnsupportedCall("can't delete attribute")

    def info2dict(self):
        dict_ = dict()
        for (key, value) in self.__dict__.items():
            if isinstance(value, Info):
                dict_[key] = value.info2dict()
            elif isinstance(value, (tuple, list, set, frozenset, collections.abc.Sequence)):
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
