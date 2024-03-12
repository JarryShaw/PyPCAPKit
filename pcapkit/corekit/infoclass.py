# -*- coding: utf-8 -*-
"""Info Class
================

.. module:: pcapkit.corekit.infoclass

:mod:`pcapkit.corekit.infoclass` contains :obj:`dict` like class
:class:`~pcapkit.corekit.infoclass.Info` only, which is originally
designed to work alike :func:`dataclasses.dataclass` as introduced
in :pep:`557`.

"""
import abc
import collections.abc
import enum
import itertools
from typing import TYPE_CHECKING, Generic, TypeVar, final

from pcapkit.utilities.compat import Mapping
from pcapkit.utilities.exceptions import UnsupportedCall, stacklevel
from pcapkit.utilities.warnings import InfoWarning, warn

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, NoReturn, Optional, Type

    from typing_extensions import Self

__all__ = ['Info', 'info_final']

VT = TypeVar('VT')
ST = TypeVar('ST', bound='Type[Info]')


class FinalisedState(enum.IntEnum):
    """Finalised state."""

    #: Not finalised.
    NONE = enum.auto()
    #: Base class.
    BASE = enum.auto()
    #: Finalised.
    FINAL = enum.auto()


def info_final(cls: 'ST', *, _finalised: 'bool' = True) -> 'ST':
    """Finalise info class.

    This decorator function is used to generate necessary
    attributes and methods for the decorated :class:`Info`
    class. It can be useful to reduce runtime generation
    time as well as caching already generated attributes.

    Notes:
        The decorator should only be used on the *final*
        class, otherwise, any subclasses derived from a
        finalised info class will not be re-finalised.

    Args:
        cls: Info class.
        _finalised: Whether to make the info class as finalised.

    Returns:
        Finalised info class.

    :meta decorator:
    """
    if cls.__finalised__ == FinalisedState.FINAL:
        warn(f'{cls.__name__}: info class has been finalised; now skipping',
             InfoWarning, stacklevel=stacklevel())
        return cls

    temp = ['__map__', '__map_reverse__', '__builtin__', '__finalised__']
    temp.extend(cls.__additional__)
    for obj in cls.mro():
        temp.extend(dir(obj))
    cls.__builtin__ = set(temp)
    cls.__excluded__.extend(cls.__builtin__)

    # NOTE: We only generate ``__init__`` method for subclasses of the
    # ``Info`` class, rather than itself, plus that such class does not
    # override the ``__init__`` method of the meta class.
    if '__init__' not in cls.__dict__ and cls is not Info:
        args_ = []  # type: list[str]
        dict_ = []  # type: list[str]

        for cls_ in cls.mro():
            # NOTE: We skip the ``Info`` class itself, to avoid superclass
            # type annotations being considered.
            if cls_ is Info:
                break

            # NOTE: We iterate in reversed order to ensure that the type
            # annotations of the superclasses are considered first.
            for key in reversed(cls_.__annotations__):
                # NOTE: We skip duplicated annotations to avoid duplicate
                # argument in function definition.
                if key in args_:
                    continue

                args_.append(key)
                dict_.append(f'{key}={key}')

        # NOTE: We reverse the two lists such that the order of the
        # arguments is the same as the order of the type annotations, i.e.,
        # from the most base class to the most derived class.
        args_.reverse()
        dict_.reverse()

        # NOTE: We only generate typed ``__init__`` method if only the class
        # has type annotations from any of itself and its base classes.
        if args_:
            # NOTE: The following code is to make the ``__init__`` method work.
            # It is inspired from the :func:`dataclasses._create_fn` function.
            init_ = (
                f'def __create_fn__():\n'
                f'    def __init__(self, {", ".join(args_)}):\n'
                f'        self.__update__({", ".join(dict_)})\n'
                f'        self.__post_init__()\n'
                f'    return __init__\n'
            )
        else:
            init_ = (
                'def __create_fn__():\n'
                '    def __init__(self, dict_=None, **kwargs):\n'
                '        self.__update__(dict_, **kwargs)\n'
                '        self.__post_init__()\n'
                '    return __init__\n'
            )

        ns = {}  # type: dict[str, Any]
        exec(init_, None, ns)  # pylint: disable=exec-used # nosec

        cls.__init__ = ns['__create_fn__']()  # type: ignore[misc]
        cls.__init__.__qualname__ = f'{cls.__name__}.__init__'  # type: ignore[misc]

    if not _finalised:
        cls.__finalised__ = FinalisedState.BASE
        return cls

    cls.__finalised__ = FinalisedState.FINAL
    return final(cls)


class InfoMeta(abc.ABCMeta):
    """Meta class to add dynamic support to :class:`Info`.

    This meta class is used to generate necessary attributes for the
    :class:`Info` class. It can be useful to reduce runtime generation
    cost as well as caching already generated attributes.

    * :attr:`Info.__additional__` and :attr:`Info.__excluded__` are
      lists of additional and excluded field names, which are used to
      determine certain names to be included or excluded from the field
      dictionary. They will be automatically populated from the class
      attributes of the :class:`Info` class and its base classes.

      .. note::

         This is implemented thru the :meth:`__new__` method, which will
         inherit the additional and excluded field names from the base
         classes, as well as populating the additional and excluded field
         from the subclass attributes.

         .. code-block:: python

            class A(Info):
                __additional__ = ['a', 'b']

            class B(A):
                __additional__ = ['c', 'd']

            class C(B):
                __additional__ = ['e', 'f']

            print(A.__additional__)  # ['a', 'b']
            print(B.__additional__)  # ['a', 'b', 'c', 'd']
            print(C.__additional__)  # ['a', 'b', 'c', 'd', 'e', 'f']

    """

    def __new__(cls, name: 'str', bases: 'tuple[type, ...]', attrs: 'dict[str, Any]', **kwargs: 'Any') -> 'Type[Info]':
        if '__additional__' not in attrs:
            attrs['__additional__'] = []
        if '__excluded__' not in attrs:
            attrs['__excluded__'] = []

        for base in bases:
            if hasattr(base, '__additional__'):
                attrs['__additional__'].extend(
                    name for name in base.__additional__ if name not in attrs['__additional__'])
            if hasattr(base, '__excluded__'):
                attrs['__excluded__'].extend(name for name in base.__excluded__ if name not in attrs['__excluded__'])
        return super().__new__(cls, name, bases, attrs, **kwargs)  # type: ignore[return-value]


class Info(Mapping[str, VT], Generic[VT], metaclass=InfoMeta):
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

    if TYPE_CHECKING:
        #: Mapping of name conflicts with builtin methods (original names to
        #: transformed names).
        __map__: 'dict[str, str]'
        #: Mapping of name conflicts with builtin methods (transformed names to
        #: original names).
        __map_reverse__: 'dict[str, str]'
        #: List of builtin methods.
        __builtin__: 'set[str]'

    #: Flag for finalised class initialisation.
    __finalised__: 'FinalisedState' = FinalisedState.NONE

    #: List of additional built-in names.
    __additional__: 'list[str]' = []
    #: List of names to be excluded from :obj:`dict` conversion.
    __excluded__: 'list[str]' = []

    def __new__(cls, *args: 'VT', **kwargs: 'VT') -> 'Self':  # pylint: disable=unused-argument
        """Create a new instance.

        The class will try to automatically generate ``__init__`` method with
        the same signature as specified in class variables' type annotations,
        which is inspired by :pep:`557` (:mod:`dataclasses`).

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        """
        if cls.__finalised__ == FinalisedState.NONE:
            cls = info_final(cls, _finalised=False)
        self = super().__new__(cls)

        # NOTE: We define the ``__map__`` and ``__map_reverse__`` attributes
        # here under ``self`` to avoid them being considered as class variables
        # and thus being shared by all instances.
        super().__setattr__(self, '__map__', {})
        super().__setattr__(self, '__map_reverse__', {})

        return self

    def __post_init__(self) -> 'None':
        """Customisation method to be called after initialisation."""

    def __update__(self, dict_: 'Optional[Mapping[str, VT] | Iterable[tuple[str, VT]]]' = None,
                   **kwargs: 'VT') -> 'None':
        # NOTE: Keys with the same names as the class's builtin methods will be
        # renamed with the class name prefixed as mangled class variables
        # implicitly and internally. Such mapping information will be stored
        # within: attr: `__map__` attribute.

        __name__ = type(self).__name__  # pylint: disable=redefined-builtin

        if dict_ is None:
            data_iter = kwargs.items()  # type: Iterable[tuple[str, Any]]
        elif isinstance(dict_, (dict, collections.abc.Mapping)) or hasattr(dict_, 'items'):
            data_iter = itertools.chain(dict_.items(), kwargs.items())
        else:
            data_iter = itertools.chain(dict_, kwargs.items())

        for (key, value) in data_iter:
            if key in self.__builtin__:
                new_key = f'_{__name__}{key}'

                # NOTE: We keep record of the mapping bidirectionally.
                self.__map__[key] = new_key
                self.__map_reverse__[new_key] = key

                key = new_key

            # if key in self.__dict__:
            #     raise KeyExists(f'{key!r} already exists')

            # NOTE: We don't rewrite the key names here, just keep the
            # original ones, even though they might break on the ``.``
            # (:obj:`getattr`) operator.

            # if isinstance(key, str):
            #     key = re.sub(r'\W', '_', key)
            self.__dict__[key] = value

    __init__ = __update__

    def __str__(self) -> 'str':
        temp = []  # type: list[str]
        for (key, value) in self.__dict__.items():
            if key in self.__excluded__:
                continue

            out_key = self.__map_reverse__.get(key, key)
            temp.append(f'{out_key}={value}')
        args = ', '.join(temp)
        return f'{type(self).__name__}({args})'

    def __repr__(self) -> 'str':
        temp = []  # type: list[str]
        for (key, value) in self.__dict__.items():
            if key in self.__excluded__:
                continue

            out_key = self.__map_reverse__.get(key, key)
            if isinstance(value, Info):
                temp.append(f'{out_key}={type(value).__name__}(...)')
            else:
                temp.append(f'{out_key}={value!r}')
        args = ', '.join(temp)
        return f'<{type(self).__name__} {args}>'

    def __len__(self) -> 'int':
        return len(self.__dict__)

    def __iter__(self) -> 'Iterator[str]':
        for key in self.__dict__:
            if key in self.__excluded__:
               continue
            yield self.__map_reverse__.get(key, key)

    def __getitem__(self, name: 'str') -> 'VT':
        key = self.__map__.get(name, name)
        return self.__dict__[key]

    def __setattr__(self, name: 'str', value: 'VT') -> 'NoReturn':
        raise UnsupportedCall("can't set attribute")

    def __delattr__(self, name: 'str') -> 'NoReturn':
        raise UnsupportedCall("can't delete attribute")

    @classmethod
    def from_dict(cls, dict_: 'Optional[Mapping[str, VT] | Iterable[tuple[str, VT]]]' = None,
                  **kwargs: 'VT') -> 'Self':
        r"""Create a new instance.

        * If ``dict_`` is present and has a ``.keys()`` method, then does:
          ``for k in dict_: self[k] = dict_[k]``.
        * If ``dict_`` is present and has no ``.keys()`` method, then does:
          ``for k, v in dict_: self[k] = v``.
        * If ``dict_`` is not present, then does:
          ``for k, v in kwargs.items(): self[k] = v``.

        Args:
            dict\_: Source data.
            **kwargs: Arbitrary keyword arguments.

        """
        self = cls.__new__(cls)
        self.__update__(dict_, **kwargs)
        return self

    def to_dict(self) -> 'dict[str, VT]':
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
            if key in self.__excluded__:
                continue

            out_key = self.__map_reverse__.get(key, key)
            if isinstance(value, Info):
                dict_[out_key] = value.to_dict()

            #elif isinstance(value, (tuple, list, set, frozenset)):
            #    temp = []  # type: list[Any]
            #    for item in value:
            #        if isinstance(item, Info):
            #            temp.append(item.to_dict())
            #        else:
            #            temp.append(item)
            #    dict_[out_key] = value.__class__(temp)

            else:
                dict_[out_key] = value
        return dict_
