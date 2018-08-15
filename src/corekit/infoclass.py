# -*- coding: utf-8 -*-
"""info class

`pcapkit.corekit.infoclass` contains dict-like class
`Info` only, which is originally designed to work alike
`dataclasses.dataclass` in Python 3.7 and later versions.

"""
import copy

from pcapkit.utilities.exceptions import UnsupportedCall
from pcapkit.utilities.validations import dict_check


__all__ = ['Info']


class Info(dict):
    """Turn dictionaries into object-like instances.

    Methods:
        * infotodict -- reverse Info object into dict type

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
                if key in dir(dict):
                    key = f'{key}2'
                if isinstance(value, dict):
                    __dict__[key] = Info(value)
                else:
                    # if isinstance(key, str):
                    #     key = re.sub(r'\W', '_', key)
                    __dict__[key] = value
            return __dict__

        self = super().__new__(cls)
        if dict_ is not None:
            if isinstance(dict_, Info):
                self = copy.deepcopy(dict_)
            else:
                dict_check(dict_)
                self.__dict__.update(__read__(dict_))

        self.__dict__.update(__read__(kwargs))
        return self

    def __repr__(self):
        temp = list()
        for (key, value) in self.__dict__.items():
            temp.append(f'{key}={value}')
        args = ', '.join(temp)
        return f'Info({args})'

    __str__ = __repr__

    def __iter__(self):
        return iter(self.__dict__)

    def __contains__(self, name):
        if name in dir(dict):
            return super().__contains__(f'{name}2')
        return super().__contains__(name)

    def __getitem__(self, key):
        if key in dir(dict):
            return super().__getitem__(f'{key}2')
        return super().__getitem__(key)

    def __setattr__(self, name, value):
        raise UnsupportedCall("can't set attribute")

    def __delattr__(self, name):
        raise UnsupportedCall("can't delete attribute")

    def infotodict(self):
        dict_ = dict()
        for (key, value) in self.__dict__.items():
            if isinstance(value, Info):
                dict_[key] = value.infotodict()
            elif isinstance(value, (tuple, list, set)):
                temp = list()
                for item in value:
                    if isinstance(item, Info):
                        temp.append(item.infotodict())
                    else:
                        temp.append(item)
                dict_[key] = value.__class__(temp)
            else:
                dict_[key] = value
        return dict_
