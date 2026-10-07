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
import sys
import types
import typing
from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.enum import EnumLookup
from pcapkit.utilities.compat import Mapping, final
from pcapkit.utilities.exceptions import InfoError, UnsupportedCall, stacklevel
from pcapkit.utilities.warnings import InfoWarning, warn

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, NoReturn, Optional, Type

    from typing_extensions import Self

__all__ = ['Info', 'info_final']

VT = TypeVar('VT')
ST = TypeVar('ST', bound='Type[Info]')


class FinalisedState(EnumLookup, enum.IntEnum):
    """Finalised state.

    Built on :class:`~pcapkit.corekit.enum.EnumLookup` per GitHub issue
    :issue:`877`'s ruling that every non-registry enumeration shares that
    lookup contract; this class defines neither ``get`` nor ``_missing_`` of
    its own.

    """

    #: Not finalised.
    NONE = enum.auto()
    #: Base class.
    BASE = enum.auto()
    #: Finalised. A class reaching this state is also handed to
    #: :func:`~pcapkit.utilities.compat.final`, so a correctly finalised class
    #: carries *both* markers -- and they answer two different questions, which
    #: is why both are read rather than one standing in for the other.
    #: ``__final__`` answers "may this be subclassed?", for
    #: :meth:`Info.__init_subclass__`; this state answers "has
    #: :func:`info_final` already generated the attributes?", for
    #: :func:`info_final`'s own re-entry check. Carrying ``__final__``
    #: *without* this state is the mismatch :meth:`Info.__new__` refuses:
    #: marked final by hand, never finalised, and so missing the generated
    #: ``__init__`` that makes the class usable at all.
    FINAL = enum.auto()


def info_final(cls: 'ST', *, _finalised: 'bool' = True) -> 'ST':
    """Finalise info class.

    This decorator function is used to generate necessary
    attributes and methods for the decorated :class:`Info`
    class. It can be useful to reduce runtime generation
    time as well as caching already generated attributes.

    Notes:
        The decorator should only be used on the *final* class. Applying it
        with ``_finalised=True`` seals the class against *subclassing*, which
        :meth:`Info.__init_subclass__` enforces, and marks it with
        :func:`~pcapkit.utilities.compat.final` -- so ``@info_final`` implies
        ``@final`` and there is never a reason to write both. Writing both is
        harmless in either order, though; what is not is ``@final`` *without*
        this decorator, which :meth:`Info.__new__` refuses -- provided ``@final``
        is :func:`~pcapkit.utilities.compat.final` (or, on Python 3.11 and up,
        :func:`typing.final` directly). Below 3.11, plain :func:`typing.final`
        does not set ``__final__`` at all (gh-90500), so a class marked with a
        user's own ``from typing import final`` on 3.10 is not refused: there is
        nothing on the class for :meth:`Info.__new__` to read.

        Applying this decorator to the same class a second time only warns: the
        first application already did the work, so the duplicate is redundant
        rather than wrong, and the class comes back finalised and usable.

    Args:
        cls: Info class.
        _finalised: Whether to make the info class as finalised.

    Returns:
        Finalised info class.

    Warns:
        pcapkit.utilities.warnings.InfoWarning: If ``cls`` has already been
            finalised *by this function*, i.e. it carries
            :attr:`FinalisedState.FINAL` in its own ``__dict__``. The class is
            returned untouched.

    :meta decorator:
    """
    # NOTE: keyed on ``__finalised__`` rather than on
    # :func:`~pcapkit.utilities.compat.final`'s ``__final__``, because the two
    # record different facts and only this one records *this function having
    # run*. Decorators apply bottom-up, so ``@info_final`` over ``@final``
    # reaches here with ``__final__`` already set by a decorator that generated
    # nothing: a ``__final__`` test would read that as "already finalised", skip
    # the generation, and hand back precisely the ``__init__``-less class
    # :meth:`Info.__new__` refuses -- while the opposite order works. Keying
    # on ``__finalised__`` is what makes the two orders agree.
    #
    # ``cls.__dict__`` rather than ``getattr``: ``__finalised__`` is an ordinary
    # class attribute and so inherited, and a subclass declared *before* its
    # parent was finalised reads FINAL through ``getattr`` while never having
    # been finalised itself. Skipping it would skip the one operation it still
    # needs -- silently, since this path only warns.
    if cls.__dict__.get('__finalised__') == FinalisedState.FINAL:
        warn(f'{cls.__name__}: info class has been finalised; now skipping',
             InfoWarning, stacklevel=stacklevel())
        return cls

    # NOTE: ``Info`` itself never reaches ``FinalisedState.BASE`` (see the
    # ``cls is not Info`` guard below), so a bare ``Info()`` re-enters this
    # function on *every* call rather than once -- and every line below this
    # point, not just the ``__excluded__`` write, would otherwise redo the same
    # ``dir()``-over-the-MRO scan each time. ``__base_ready__`` is a marker of
    # its own, separate from ``__finalised__``, that records only "this base
    # class's one-time setup already ran" -- checked and set in ``Info``'s own
    # ``__dict__`` alone, so it is invisible to every check keyed on
    # ``__finalised__`` staying ``NONE``. A subclass is never affected: it is
    # promoted to ``BASE`` on its own first call and never reaches here again.
    if cls is Info and cls.__dict__.get('__base_ready__'):
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

        for cls_ in cls.mro():  # pragma: no branch
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
        # NOTE: ``Info`` itself must never receive this promotion. ``__finalised__``
        # is an ordinary class attribute, and this branch is only ever reached with
        # ``cls`` bound to ``Info`` when something bare-constructs ``Info()``
        # directly -- every real subclass reaches :meth:`Info.__new__` with ``cls``
        # bound to itself. Writing ``BASE`` onto ``Info.__dict__`` would therefore
        # make *every* subclass declared afterwards inherit ``BASE`` from ``Info``,
        # so its own ``cls.__finalised__ == FinalisedState.NONE`` test in
        # :meth:`Info.__new__` would never see ``NONE`` again -- silently defeating
        # both that one-shot auto-finalisation and the bare-``@final`` guard nested
        # inside it, for every class declared after the first bare ``Info()``
        # anywhere in the process. See GitHub issue #778's cross-review, which
        # demonstrated the bypass with a class declared after such a call.
        #
        # ``__base_ready__`` is set instead, for the short-circuit at the top of
        # this function -- own-``__dict__`` only, so it neither inherits nor
        # touches ``__finalised__``.
        if cls is not Info:
            cls.__finalised__ = FinalisedState.BASE
        else:
            cls.__base_ready__ = True
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

    * :class:`Info` objects are :class:`~collections.abc.Mapping` instances,
      not :obj:`dict` subclasses
    * :class:`Info` objects are *iterable*, and support the read-only
      :obj:`dict` interface
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

    def __init_subclass__(cls, /, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Refuse to derive from a finalised info class.

        :func:`~pcapkit.utilities.compat.final` is a promise to the type
        checker and nothing more: it records ``__final__`` on the class and
        leaves the interpreter free to subclass it anyway. Every class
        :func:`info_final` finalises carries a generated ``__init__`` built
        from the annotations that were visible at that moment, so a subclass
        added afterwards inherits a constructor that does not know about its
        own fields -- silently, and with the ``__builtin__`` and
        ``__excluded__`` sets of its parent. This turns that promise into a
        rule the interpreter keeps.

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments in class definition.

        Raises:
            InfoError: If any class in ``cls``'s ancestry carries the
                ``__final__`` marker in its own ``__dict__``.

        """
        # NOTE: the whole ancestry rather than ``cls.__bases__``, because the
        # direct bases alone leave a one-line way round the rule: declare the
        # subclass *before* applying the decorator to its parent, and every
        # further descendant of that subclass is then unguarded, since the
        # marker sits two levels up rather than one. Walking the MRO costs one
        # dict lookup per ancestor, once per class declaration.
        #
        # ``base.__dict__`` rather than ``getattr`` for the reason given in
        # :func:`info_final`: ``__final__`` is inherited, so a ``getattr`` here
        # would read it off every descendant and reject declarations that
        # predate the marker rather than the ones the rule is about.
        for base in cls.__mro__[1:]:
            if base.__dict__.get('__final__'):
                raise InfoError(f'{cls.__name__}: cannot subclass {base.__name__}, '
                                'which is final')

        # NOTE: ``*args`` and ``**kwargs`` are forwarded rather than swallowed, so
        # that a class keyword nobody accepts still reaches ``object`` and fails
        # there.
        super().__init_subclass__(*args, **kwargs)

    def __new__(cls, *args: 'VT', **kwargs: 'VT') -> 'Self':  # pylint: disable=unused-argument
        """Create a new instance.

        The class will try to automatically generate ``__init__`` method with
        the same signature as specified in class variables' type annotations,
        which is inspired by :pep:`557` (:mod:`dataclasses`).

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            InfoError: If ``cls`` was marked with
                :func:`~pcapkit.utilities.compat.final` but never finalised by
                :func:`info_final`, i.e. it carries ``__final__`` in its own
                ``__dict__`` without :attr:`FinalisedState.FINAL`.

        Warning:
            Out of scope, deliberately: a ``@final`` class descending from a
            :attr:`FinalisedState.BASE` ancestor is not caught. ``__finalised__``
            inherits, and a ``BASE`` ancestor means some earlier bare
            construction already walked this branch for the chain -- so the
            subclass's own ``cls.__finalised__`` reads ``BASE`` too, the branch
            below is skipped entirely, and the marker on ``cls`` itself is never
            inspected. Closing this means re-finalising every descendant of a
            ``BASE`` class on each subclassing, which is the auto-finalisation
            behaviour ``test_an_unfinalised_descendant_is_not_mistaken_for_a_
            mismarked_class`` deliberately leaves alone. In the tree today no
            ``BASE``-state class is ever marked ``@final`` by hand, so the escape
            is theoretical rather than live.

        """
        # NOTE: ``final`` is applied *after* the class object exists, so
        # :meth:`__init_subclass__` has already run and returned by the time a
        # bare ``@final`` lands -- it cannot see the mistake, and no other
        # class-creation hook fires later. First instantiation is the next event
        # in the class's life this library controls, and it is also where the
        # damage surfaces: an unfinalised class has no generated ``__init__``, so
        # construction would fall through to :meth:`__update__` and fail with
        # ``TypeError: 'int' object is not iterable``, naming neither the class
        # nor the mistake.
        #
        # It is nested inside the NONE branch rather than run ahead of it, and
        # that placement is what makes it free on the hot path: a finalised class
        # never enters the branch at all, so it never evaluates the nested
        # ``cls.__dict__.get('__final__')`` either -- ``dis.dis(Info.__new__)``
        # shows the ``FinalisedState.NONE`` comparison compiles to a single
        # ``POP_JUMP_IF_FALSE`` that, for a ``FINAL`` class, jumps straight past
        # this whole block to ``super().__new__``: zero of the added bytecode
        # executes, which is a property of the compiled branch rather than of
        # any particular timing run, and is the reason to trust here rather than
        # a timer. The raise also leaves ``__finalised__`` at NONE, so a second
        # attempt re-enters and fails again rather than the error firing once.
        #
        # ``cls.__dict__`` rather than ``getattr``: not because a class that
        # inherits ``__final__`` from a *finalised* ancestor would be misread --
        # such a class also inherits ``__finalised__ == FINAL``, so the outer
        # ``if`` above already excludes it before this line is ever reached,
        # regardless of which lookup is used here. The case ``getattr`` gets
        # wrong is an ancestor hand-marked bare ``@final`` and *never finalised*:
        # its own ``__finalised__`` stays ``NONE`` and so, inherited, does every
        # subclass declared before the marker landed -- so such a subclass still
        # reaches this line, and ``getattr`` would read the marker it merely
        # inherits and blame it for a mismarking that is its ancestor's, not its
        # own. ``OwnDictRuleTests.test_a_subclass_that_predates_an_unfinalised_
        # ancestors_bare_final_is_not_blamed_for_it`` pins exactly this shape --
        # mutating this line to ``getattr`` fails it.
        if cls.__finalised__ == FinalisedState.NONE:
            if cls.__dict__.get('__final__'):
                raise InfoError(f'{cls.__name__}: marked final but never finalised, so it has no generated '
                                '__init__; apply info_final, which applies final itself, not final alone')
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
        # within the :attr:`__map__` attribute.

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
        # NOTE: count exactly the keys :meth:`__iter__` yields, so the
        # bookkeeping attributes in ``__excluded__`` are not counted.
        return sum(1 for key in self.__dict__ if key not in self.__excluded__)

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

        A mapping given for a key whose type annotation resolves at runtime to
        an :class:`Info` subclass (or to :data:`~typing.Optional` of one) is
        rebuilt into that class, so ``cls.from_dict(info.to_dict())`` restores
        such nested values. A key without such an annotation keeps the mapping
        as is -- see :meth:`to_dict`.

        The rebuild is as unchecked as the rest of this method: a mapping whose
        keys are not the nested class's own is accepted and becomes an instance
        carrying those keys, exactly as a direct call to the nested class's own
        :meth:`from_dict` would. Validating it here would reject data that
        ``Info(**kwargs)`` has always accepted, so the shape of the mapping
        stays the caller's responsibility.

        Args:
            dict\_: Source data.
            **kwargs: Arbitrary keyword arguments.

        """
        self = cls.__new__(cls)
        self.__update__(dict_, **kwargs)

        for (name, info_cls) in _nested_info_types(cls).items():
            key = self.__map__.get(name, name)
            value = self.__dict__.get(key)
            if isinstance(value, Mapping) and not isinstance(value, Info):
                self.__dict__[key] = info_cls.from_dict(value)
        return self

    def to_dict(self) -> 'dict[str, VT]':
        """Convert :class:`Info` into :obj:`dict`.

        Important:
            We only convert nested :class:`Info` objects into :obj:`dict` if
            they are the direct value of the :class:`Info` object's attribute.
            Should such :class:`Info` objects be nested within other data,
            types, such as :obj:`list`, :obj:`tuple`, :obj:`set`, etc., we
            shall not convert them into :obj:`dict` and remain them intact.

        Note:
            :meth:`from_dict` reverses the flattening only for keys whose type
            annotation resolves at runtime to an :class:`Info` subclass. For
            any other key -- every key of a bare :class:`Info`, and annotations
            naming a type imported only under :data:`~typing.TYPE_CHECKING` --
            the conversion is one-way, and the nested value comes back as a
            plain :obj:`dict`.

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


#: Name of the per-class attribute :func:`_nested_info_types` caches its answer in.
_NESTED_INFO_CACHE = '__nested_info_types__'

#: :pep:`604` union type, i.e. the origin of ``int | None``. It is absent below
#: Python 3.10, where only :data:`typing.Optional` spells a union, and is the
#: same object as :data:`typing.Union` from 3.14 on.
_UNION_TYPE = getattr(types, 'UnionType', None)

#: Type of :data:`None`, i.e. the member ``Optional`` adds to a union.
_NONE_TYPE = type(None)


def _as_info_type(hint: 'Any') -> 'Optional[Type[Info]]':
    """Return the :class:`Info` subclass a resolved annotation names, if any.

    :data:`~typing.Optional` of a single :class:`Info` subclass counts as that
    subclass. A parametrised generic such as ``list[Packet]`` does not: the
    value it describes is a container, and :meth:`Info.from_dict` has nothing
    to rebuild it from.

    Args:
        hint: Resolved type annotation.

    Returns:
        The :class:`Info` subclass the annotation names, or :data:`None`.

    Note:
        Both guards below are load-bearing on Python 3.9 and 3.10, where a
        :class:`types.GenericAlias` such as ``list[Packet]`` satisfies
        ``isinstance(hint, type)`` while :func:`issubclass` still refuses it
        with :exc:`TypeError` -- which would otherwise escape
        :meth:`Info.from_dict` for the 26 of 487 :class:`Info` classes that
        carry such an annotation. From 3.11 on the ``isinstance`` is already
        :data:`False`, so only the older interpreters reach the
        :exc:`TypeError`; ``NestedTypeResolverTests`` in
        :file:`tests/corekit/test_from_dict_roundtrip_unit.py` pins the shape
        on every version by handing this function an object that mimics it.

    """
    origin = typing.get_origin(hint)
    if origin is not None or not isinstance(hint, type):
        # NOTE: a union of exactly one non-``None`` member is ``Optional`` of
        # that member, so it unwraps to it; anything else is not an ``Info``.
        args = [arg for arg in getattr(hint, '__args__', ()) if arg is not _NONE_TYPE]
        is_union = origin is typing.Union or (_UNION_TYPE is not None and origin is _UNION_TYPE)
        hint = args[0] if is_union and len(args) == 1 else None

    if not isinstance(hint, type):
        return None

    try:
        return hint if issubclass(hint, Info) else None
    except TypeError:
        return None


def _nested_info_types(cls: 'Type[Info]') -> 'dict[str, Type[Info]]':
    """Map the keys of ``cls`` annotated with an :class:`Info` subclass to it.

    Each annotation is resolved on its own, in the namespace of the module and
    the class that declared it, so one that cannot be resolved at runtime (e.g.
    a name imported only under :data:`~typing.TYPE_CHECKING`) is skipped rather
    than spoiling the rest.

    Args:
        cls: Info class.

    Returns:
        Mapping of key names to the :class:`Info` subclass annotated for them.

    Note:
        The answer is cached in ``cls``'s own ``__dict__``, read back from
        there rather than through :func:`getattr` so a subclass never inherits
        its parent's map. The cache is deliberately kept on the class rather
        than in a module-level :class:`weakref.WeakKeyDictionary`: such a map
        would pin every self-referential class forever, since the cached value
        strongly references the class the weak key points at, whereas the
        reference cycle a class attribute creates is collectable.

        An unresolvable annotation is cached as "skip" alongside the rest, so a
        forward reference whose target is defined only *after* the first
        :meth:`Info.from_dict` call stays one-way for the life of the process.
        That is accepted rather than fixed: :meth:`Info.from_dict` runs per
        parsed packet (see :meth:`IPv4._read_ipv4_options
        <pcapkit.protocols.internet.ipv4.IPv4._read_ipv4_options>`), and
        re-resolving the annotations on every call to catch a case that does
        not arise in this package costs far more than it saves.

    """
    cached = cls.__dict__.get(_NESTED_INFO_CACHE)
    if cached is not None:
        return cached

    nested = {}  # type: dict[str, Type[Info]]
    seen = set()  # type: set[str]
    for cls_ in cls.mro():  # pragma: no branch
        # NOTE: same walk as :func:`info_final`, which builds ``__init__``
        # from these annotations; the most derived declaration of a key wins.
        if cls_ is Info:
            break

        module = sys.modules.get(cls_.__module__)
        globalns = dict(vars(module)) if module is not None else {}
        localns = dict(vars(cls_))
        for (key, ann) in cls_.__dict__.get('__annotations__', getattr(cls_, '__annotations__', {})).items():
            if key in seen:
                continue
            seen.add(key)

            try:
                hint = typing.get_type_hints(types.SimpleNamespace(__annotations__={key: ann}),
                                             globalns, localns)[key]
            except Exception:  # pylint: disable=broad-except
                continue

            info_cls = _as_info_type(hint)
            if info_cls is not None:
                nested[key] = info_cls

    setattr(cls, _NESTED_INFO_CACHE, nested)
    return nested
