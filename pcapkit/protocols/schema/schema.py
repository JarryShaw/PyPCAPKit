# -*- coding: utf-8 -*-
"""schema for protocol headers"""

import abc
import collections
import collections.abc
import io
import itertools
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.field import FieldBase, NoValue
from pcapkit.corekit.fields.misc import ConditionalField, ForwardMatchField, PayloadField
from pcapkit.corekit.fields.strings import PaddingField
from pcapkit.corekit.infoclass import FinalisedState
from pcapkit.utilities.compat import Mapping, final
from pcapkit.utilities.decorators import prepare
from pcapkit.utilities.exceptions import NoDefaultValue, ProtocolUnbound, SchemaError, stacklevel
from pcapkit.utilities.warnings import RegistryWarning, SchemaWarning, UnknownFieldWarning, warn

if TYPE_CHECKING:
    from collections import OrderedDict
    from enum import Enum
    from typing import IO, Any, Callable, DefaultDict, Iterable, Iterator, Optional, Type

    from typing_extensions import Self

__all__ = ['Schema', 'EnumSchema', 'schema_final']

_VT = TypeVar('_VT')
_ET = TypeVar('_ET', bound='Enum')
_ST = TypeVar('_ST', bound='Type[Schema]')


def schema_final(cls: '_ST', *, _finalised: 'bool' = True) -> '_ST':
    """Finalise schema class.

    This decorator function is used to generate necessary
    attributes and methods for the decorated :class:`Schema`
    class. It can be useful to reduce runtime generation
    time as well as caching already generated attributes.

    Notes:
        The decorator should only be used on the *final* class. Applying it
        with ``_finalised=True`` seals the class against *subclassing*, which
        :meth:`Schema.__init_subclass__` enforces, and marks it with
        :func:`~pcapkit.utilities.compat.final` -- so ``@schema_final`` implies
        ``@final`` and there is never a reason to write both. Writing both is
        harmless in either order, though; what is not is ``@final`` *without*
        this decorator, which :meth:`Schema.__new__` refuses -- provided
        ``@final`` is :func:`~pcapkit.utilities.compat.final` (or, on Python
        3.11 and up, :func:`typing.final` directly). Below 3.11, plain
        :func:`typing.final` does not set ``__final__`` at all (gh-90500), so a
        class marked with a user's own ``from typing import final`` on 3.10 is
        not refused: there is nothing on the class for :meth:`Schema.__new__` to
        read.

        Applying this decorator to the same class a second time only warns: the
        first application already did the work, so the duplicate is redundant
        rather than wrong, and the class comes back finalised and usable.

    Args:
        cls: Schema class.
        _finalised: Whether to make the schema class finalised.

    Returns:
        Finalised schema class.

    Warns:
        pcapkit.utilities.warnings.SchemaWarning: If ``cls`` has already been
            finalised *by this function*, i.e. it carries
            :attr:`~pcapkit.corekit.infoclass.FinalisedState.FINAL` in its own
            ``__dict__``. The class is returned untouched.

    :meta decorator:
    """
    # NOTE: keyed on ``__finalised__`` rather than on ``final``'s ``__final__``,
    # and read out of ``cls.__dict__`` rather than through ``getattr``. See
    # :func:`pcapkit.corekit.infoclass.info_final`, which makes both choices for
    # the same two reasons: only ``__finalised__`` records *this function* having
    # run, so a ``__final__`` test would make ``@schema_final`` over ``@final``
    # skip the generation while the opposite order did the work; and
    # ``__finalised__`` is inherited, so ``getattr`` would skip a subclass
    # declared before its parent was finalised.
    if cls.__dict__.get('__finalised__') == FinalisedState.FINAL:
        warn(f'{cls.__name__}: schema has been finalised; now skipping',
             SchemaWarning, stacklevel=stacklevel())
        return cls

    # NOTE: short-circuit for ``Schema`` itself -- see the identical NOTE in
    # :func:`pcapkit.corekit.infoclass.info_final`, which makes the same fix for
    # the same reason: ``Schema`` never reaches ``FinalisedState.BASE`` now, so a
    # bare ``Schema()`` would otherwise re-enter this function, and redo the
    # ``dir()``-over-the-MRO scan below, on *every* call. ``__base_ready__`` is
    # its own marker, own-``__dict__`` only, so it never touches ``__finalised__``.
    if cls is Schema and cls.__dict__.get('__base_ready__'):
        return cls

    temp = ['__map__', '__map_reverse__', '__builtin__',
            '__fields__', '__buffer__', '__updated__',
            '__payload__', '__finalised__']
    temp.extend(cls.__additional__)
    for obj in cls.mro():
        temp.extend(el for el in dir(obj) if el not in cls.__fields__)
    cls.__builtin__ = set(temp)
    cls.__excluded__.extend(cls.__builtin__)

    args_ = [f'{key}=NoValue' for key in cls.__fields__]
    dict_ = [f'{key}={key}' for key in cls.__fields__]

    # NOTE: We shall only attempt to generate ``__init__`` method if the class
    # does not define such method -- which is a test on ``cls.__dict__``, not on
    # ``hasattr``: every class inherits ``__init__`` from :obj:`object`, so
    # ``hasattr(cls, '__init__')`` is unconditionally true and the generated
    # method was never installed. ``Schema(...)`` therefore ran
    # :meth:`Schema.__update__` alone and never reached
    # :meth:`Schema.__post_init__`, leaving a schema built from a subset of its
    # fields holding :class:`~pcapkit.corekit.fields.field.FieldBase` objects in
    # place of the omitted values, so that it could not be packed at all and
    # failed with an error naming a field class rather than a field. See #422.
    #
    # :class:`~pcapkit.protocols.schema.misc.null.NoPayload` is what the test
    # protects: it declares an argument-less ``__init__`` of its own so that no
    # generated one displaces it.
    if '__init__' not in cls.__dict__:
        # NOTE: We only generate typed ``__init__`` method if only the class
        # has field definition from any of itself and its base classes.
        if args_:
            # NOTE: The following code is to make the ``__init__`` method work.
            # It is inspired from the :func:`dataclasses._create_fn` function.
            #
            # ``**kwargs`` is forwarded rather than rejected, so that a keyword
            # naming something other than a field keeps reaching
            # :meth:`Schema.__update__` and drawing its
            # :class:`~pcapkit.utilities.warnings.UnknownFieldWarning`, as it did
            # while ``__init__`` *was* ``__update__``. Several schemas are
            # constructed that way on purpose -- the Multipath TCP options take a
            # ``kind`` and a ``length`` that the enclosing option owns and that
            # ``MPTCP`` declares only for the type checker -- so a strict
            # signature here would turn a warning into a :exc:`TypeError` on a
            # path that has nothing to do with the missing ``__post_init__``.
            init_ = (
                f'def __create_fn__():\n'
                f'    def __init__(self, {", ".join(args_)}, *, __packet__=None, **kwargs):\n'
                f'        self.__update__({", ".join(dict_)}, **kwargs)\n'
                f'        self.__post_init__(__packet__)\n'
                f'    return __init__\n'
            )
        else:
            init_ = (
                'def __create_fn__():\n'
                '    def __init__(self, dict_=None, *, __packet__=None, **kwargs):\n'
                '        self.__update__(dict_, **kwargs)\n'
                '        self.__post_init__(__packet__)\n'
                '    return __init__\n'
            )

        ns = {}  # type: dict[str, Any]
        exec(init_, None, ns)  # pylint: disable=exec-used # nosec

        cls.__init__ = ns['__create_fn__']()  # type: ignore[misc]
        cls.__init__.__qualname__ = f'{cls.__name__}.__init__'  # type: ignore[misc]

    if not _finalised:
        # NOTE: ``Schema`` itself must never receive this promotion, for the same
        # reason ``Info`` must not -- see :func:`pcapkit.corekit.infoclass.info_final`,
        # which makes the identical fix. This branch binds ``cls`` to ``Schema``
        # only when something bare-constructs ``Schema()`` directly, and writing
        # ``BASE`` onto ``Schema.__dict__`` there would make every subclass declared
        # afterwards inherit ``BASE`` and skip :meth:`Schema.__new__`'s own
        # ``FinalisedState.NONE`` branch -- silently defeating the bare-``@final``
        # guard nested inside it for the rest of the process.
        #
        # ``__base_ready__`` is set instead, for the short-circuit at the top of
        # this function -- own-``__dict__`` only, so it neither inherits nor
        # touches ``__finalised__``.
        if cls is not Schema:
            cls.__finalised__ = FinalisedState.BASE
        else:
            cls.__base_ready__ = True
        return cls

    cls.__finalised__ = FinalisedState.FINAL
    return final(cls)


class SchemaMeta(abc.ABCMeta):
    """Meta class to add dynamic support to :class:`Schema`.

    This meta class is used to generate necessary attributes for the
    :class:`Schema` class. It can be useful to reduce runtime generation
    cost as well as caching already generated attributes.

    * :attr:`Schema.__fields__` is a dictionary of field names and their
      corresponding :class:`~pcapkit.corekit.fields.field.Field` objects,
      which are used to define and parse the protocol headers. The field
      dictionary will automatically be populated from the class attributes
      of the :class:`Schema` class, and the field names will be the same
      as the attribute names.

      .. seealso::

         This is implemented thru setting up the initial field dictionary
         in the |prepare|_ method, and then inherit the field
         dictionaries from the base classes.

         Later, during the class creation, the
         :meth:`Field.__set_name__ <pcapkit.corekit.fields.field.FieldBase.__set_name__>`
         method will be called to set the field name for each field object,
         as well as to add the field object to the field dictionary.

         .. |prepare| replace:: :meth:`__prepare__`
         .. _prepare: https://docs.python.org/3/reference/datamodel.html#preparing-the-class-namespace

    * :attr:`Schema.__additional__` and :attr:`Schema.__excluded__` are
      lists of additional and excluded field names, which are used to
      determine certain names to be included or excluded from the field
      dictionary. They will be automatically populated from the class
      attributes of the :class:`Schema` class and its base classes.

      .. note::

         This is implemented thru the :meth:`~object.__new__` method, which
         will inherit the additional and excluded field names from the base
         classes, as well as populating the additional and excluded field
         from the subclass attributes.

         .. code-block:: python

            class A(Schema):
                __additional__ = ['a', 'b']

            class B(A):
                __additional__ = ['c', 'd']

            class C(B):
                __additional__ = ['e', 'f']

            print(A.__additional__)  # ['a', 'b']
            print(B.__additional__)  # ['a', 'b', 'c', 'd']
            print(C.__additional__)  # ['a', 'b', 'c', 'd', 'e', 'f']

    """

    @classmethod
    def __prepare__(cls, name: 'str', bases: 'tuple[type, ...]', /, **kwds: 'Any') -> 'Mapping[str, object]':
        """Prepare the namespace for the schema class.

        Args:
            name: Name of the schema class.
            bases: Base classes of the schema class.
            **kwds: Additional keyword arguments at class definition.

        This method is used to create the initial field dictionary
        :attr:`~Schema.__fields__` for the schema class.

        """
        fields = collections.OrderedDict()
        for base in bases:
            if hasattr(base, '__fields__'):
                fields.update(base.__fields__)
        return collections.OrderedDict(__fields__=fields)

    #: Class keywords that collide with a parameter this class does not
    #: control, so a schema class declared with one fails with an opaque
    #: ``TypeError`` from several frames away instead of a clear message here.
    #: Two different collisions, both reserved:
    #:
    #: ``mcls``, ``name``, ``bases``, ``namespace`` collide with
    #: :meth:`abc.ABCMeta.__new__` -- a *different* function from this one, one
    #: level up the ``super().__new__(...)`` call below. Before Python 3.11
    #: those four are positional-or-keyword there (from 3.11 they are
    #: positional-only, ``def __new__(mcls, name, bases, namespace, /,
    #: **kwargs)``), so a class keyword spelled the same as any of them binds
    #: that parameter twice: ``TypeError: ABCMeta.__new__() got multiple
    #: values for argument '...'``. That is GitHub issue #439's root cause --
    #: ``namespace`` collided this way, which is why
    #: :mod:`pcapkit.protocols.schema.misc.pcapng`'s ``Option`` subclasses
    #: spell it ``ns=`` instead.
    #:
    #: ``cls`` collides one level *later*: every ``__init_subclass__`` is an
    #: implicit classmethod, so ``cls`` is always bound as its first argument,
    #: and a class keyword also spelled ``cls`` binds it twice there --
    #: ``TypeError: Generic.__init_subclass__() got multiple values for
    #: argument 'cls'`` for a :class:`Schema` subclass (:class:`Schema`
    #: inherits :class:`typing.Generic`), or the equivalent from whichever
    #: class in the MRO defines ``__init_subclass__`` first. This one is not
    #: specific to ``abc.ABCMeta`` or to this metaclass at all -- it holds for
    #: *any* Python class with any ``__init_subclass__`` in its MRO -- but it
    #: is reserved here anyway since it is exactly the class of mistake this
    #: guard exists to catch early and legibly.
    #:
    #: Listed explicitly rather than derived from
    #: :func:`inspect.signature(abc.ABCMeta.__new__) <inspect.signature>` at
    #: import time: the signature's positional-only marker differs across
    #: Python versions, introspecting a CPython internal's exact shape to
    #: guard against a CPython internal's exact shape is circular, and five
    #: names that will not change are cheaper to read than the machinery to
    #: recompute them.
    #:
    #: ``name``, ``bases`` and ``attrs`` -- *this* method's own parameters --
    #: collide the same way one level earlier than ``ABCMeta.__new__``, on
    #: every Python version, and are not in this set for that reason alone:
    #: they are made positional-only below instead (the same fix CPython gave
    #: ``ABCMeta.__new__`` in 3.11), which removes the collision rather than
    #: merely naming it. ``name`` and ``bases`` stay in this set regardless,
    #: because they still collide with ``ABCMeta.__new__``'s parameters of the
    #: same name one level up; ``attrs`` does not appear anywhere downstream
    #: and so needs no entry once it is positional-only here.
    _RESERVED_CLASS_KWARGS = frozenset({'mcls', 'name', 'bases', 'namespace', 'cls'})

    def __new__(cls, name: 'str', bases: 'tuple[type, ...]', attrs: 'dict[str, Any]', /, **kwargs: 'Any') -> 'Type[Schema]':
        """Create the schema class.

        Args:
            name: Schema class name.
            bases: Schema class bases.
            attrs: Schema class attributes.
            **kwargs: Arbitrary keyword arguments in class definition.

        This method is used to inherit the :attr:`~Schema.__additional__` and
        :attr:`~Schema.__excluded__` fields from the base classes, as well as
        populating both fields from the subclass attributes.

        Raises:
            SchemaError: If a class keyword in ``**kwargs`` collides with a
                parameter of :meth:`abc.ABCMeta.__new__` or of
                ``__init_subclass__`` -- see :attr:`_RESERVED_CLASS_KWARGS`.

        """
        if clash := cls._RESERVED_CLASS_KWARGS.intersection(kwargs):
            raise SchemaError(
                f'{name}: class keyword(s) {sorted(clash)!r} are reserved -- '
                f'each collides with a same-named parameter of either '
                f'abc.ABCMeta.__new__ or the implicit __init_subclass__ '
                f'classmethod binding, and cannot be used as a class keyword '
                f'on a Schema subclass; rename to a different spelling (see '
                f'GitHub issue #439)'
            )

        if '__additional__' not in attrs:
            attrs['__additional__'] = []
        if '__excluded__' not in attrs:
            attrs['__excluded__'] = []

        for base in bases:
            if hasattr(base, '__additional__'):
                attrs['__additional__'].extend(name for name in base.__additional__ if name not in attrs['__additional__'])
            if hasattr(base, '__excluded__'):
                attrs['__excluded__'].extend(name for name in base.__excluded__ if name not in attrs['__excluded__'])

        # See #439: this used to branch on ``sys.version_info < (3, 11)`` and
        # call ``type.__new__`` directly below that, to dodge the ``namespace``
        # collision described above. That branch skipped ``ABCMeta.__new__``'s
        # call to ``abc._abc_init(cls)``, so no :class:`Schema` subclass ever
        # got its own ``_abc_impl``, and every one of them fell through the
        # MRO to :class:`collections.abc.Mapping`'s -- corrupting
        # ``isinstance`` against *any* of them for as long as the process ran.
        # The actual fix was renaming the one colliding class keyword that was
        # actually in use, which means this can now call ``ABCMeta.__new__``
        # unconditionally, on every supported version, like any other
        # metaclass would.
        return super().__new__(cls, name, bases, attrs, **kwargs)  # type: ignore[return-value]


class Schema(Mapping[str, _VT], Generic[_VT], metaclass=SchemaMeta):
    """Schema for protocol headers."""

    if TYPE_CHECKING:
        #: Mapping of name conflicts with builtin methods (original names to
        #: transformed names).
        __map__: 'dict[str, str]'
        #: Mapping of name conflicts with builtin methods (transformed names to
        #: original names).
        __map_reverse__: 'dict[str, str]'
        #: List of builtin methods.
        __builtin__: 'set[str]'
        #: Mapping of fields.
        __fields__: 'OrderedDict[str, FieldBase]'
        #: Mapping of field names to packed values.
        __buffer__: 'dict[str, bytes]'
        #: Flag for whether the schema is recently updated.
        __updated__: 'bool'

    #: Flag for finalised class initialisation.
    __finalised__: 'FinalisedState' = FinalisedState.NONE

    #: Field name of the payload.
    __payload__: 'str' = 'payload'
    #: List of additional built-in names.
    __additional__: 'list[str]' = []
    #: List of names to be excluded from :obj:`dict` conversion.
    __excluded__: 'list[str]' = []

    def __init_subclass__(cls, /, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Refuse to derive from a finalised schema.

        :func:`~pcapkit.utilities.compat.final` is a promise to the type
        checker and nothing more: it records ``__final__`` on the class and
        leaves the interpreter free to subclass it anyway. Every schema
        :func:`schema_final` finalises carries a generated ``__init__`` built
        from the :attr:`__fields__` that were declared at that moment, so a
        subclass adding a field afterwards inherits a constructor that cannot
        set it -- which is #422's failure shape, reached by a different route.
        This turns that promise into a rule the interpreter keeps.

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments in class definition.

        Raises:
            SchemaError: If any class in ``cls``'s ancestry carries the
                ``__final__`` marker in its own ``__dict__``.

        """
        # NOTE: the whole ancestry rather than ``cls.__bases__``, and
        # ``base.__dict__`` rather than ``getattr`` -- see
        # :meth:`pcapkit.corekit.infoclass.Info.__init_subclass__`, which makes
        # the same two choices for the same two reasons.
        for base in cls.__mro__[1:]:
            if base.__dict__.get('__final__'):
                raise SchemaError(f'{cls.__name__}: cannot subclass {base.__name__}, '
                                  'which is final')

        # NOTE: forwarded rather than swallowed, so that a class keyword nobody
        # accepts still reaches ``object`` and still fails there, as it did before
        # this hook existed. :meth:`EnumSchema.__init_subclass__` is the one caller
        # that reaches here with nothing: it consumes its own ``code`` keyword and
        # discards the rest, which is why a stray class keyword is tolerated on an
        # :class:`EnumSchema` subclass and rejected on a plain one. That asymmetry
        # predates this method and is left alone.
        super().__init_subclass__(*args, **kwargs)

    def __new__(cls, *args: '_VT', **kwargs: '_VT') -> 'Self':  # pylint: disable=unused-argument
        """Create a new instance.

        The class will try to automatically generate ``__init__`` method with
        the same signature as specified in class variables' type annotations,
        which is inspired by :pep:`557` (:mod:`dataclasses`).

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            SchemaError: If ``cls`` was marked with
                :func:`~pcapkit.utilities.compat.final` but never finalised by
                :func:`schema_final`, i.e. it carries ``__final__`` in its own
                ``__dict__`` without
                :attr:`~pcapkit.corekit.infoclass.FinalisedState.FINAL`.

        Warning:
            Out of scope, deliberately -- see
            :meth:`pcapkit.corekit.infoclass.Info.__new__`, which documents the
            identical gap: a ``@final`` class descending from a
            :attr:`~pcapkit.corekit.infoclass.FinalisedState.BASE` ancestor
            inherits ``BASE`` rather than ``NONE`` and so never reaches the
            branch below at all, regardless of its own marker. No ``BASE``-state
            schema in the tree is marked ``@final`` by hand today, so the escape
            is theoretical rather than live.

        """
        # NOTE: first instantiation is the earliest point a bare ``@final`` can
        # be caught -- ``final`` runs after the class object exists, so
        # :meth:`__init_subclass__` has already returned. Nested inside the NONE
        # branch, which is already one-shot per class, so a finalised schema pays
        # nothing for it. See :meth:`pcapkit.corekit.infoclass.Info.__new__`,
        # which carries the full reasoning and the measurement; on this side the
        # missing generated ``__init__`` is the one built from
        # :attr:`__fields__`, so the damage is #422's shape.
        if cls.__finalised__ == FinalisedState.NONE:
            if cls.__dict__.get('__final__'):
                raise SchemaError(f'{cls.__name__}: marked final but never finalised, so it has no generated '
                                  '__init__; apply schema_final, which applies final itself, not final alone')
            cls = schema_final(cls, _finalised=False)
        self = super().__new__(cls)

        # NOTE: We define the ``__map__`` and ``__map_reverse__`` attributes
        # here under ``self`` to avoid them being considered as class variables
        # and thus being shared by all instances.
        super().__setattr__(self, '__map__', {})
        super().__setattr__(self, '__map_reverse__', {})

        # NOTE: We only create the attributes for the instance itself,
        # to avoid creating shared attributes for the class.
        super().__setattr__(self, '__buffer__', {name: b'' for name in self.__fields__.keys()})
        super().__setattr__(self, '__updated__', True)

        return self

    def __post_init__(self, packet: 'Optional[dict[str, Any]]' = None) -> 'None':
        """Fill in the fields the caller left unset.

        Args:
            packet: Packet data, as forwarded from the ``__packet__`` keyword
                argument of the generated ``__init__``. The schema is packed
                here only when one is given; see the note below.

        """
        for name, field in self.__fields__.items():
            # NOTE: Read with a fallback rather than by subscript, since the
            # generated ``__init__`` is not the only caller: :meth:`from_dict`
            # seeds only the keys its argument carries, so a field the caller left
            # out is missing from ``__dict__`` entirely rather than holding
            # ``NoValue``, and subscripting it raised :exc:`KeyError` naming the
            # field.
            #
            # What is tested is ``NoValue`` alone, not ``NoValue`` or ``None``.
            # This method fills in what the caller did not say, and a ``None`` the
            # caller passed *is* something said: on an optional field it is the
            # chosen value, meaning this packet does not carry the field. It is
            # also what :meth:`unpack` stores for a
            # :class:`~pcapkit.corekit.fields.misc.ConditionalField` whose test
            # fails -- including one that declares a default of its own -- so
            # substituting the default here would leave a constructed schema
            # disagreeing with a parsed one about the same packet, and
            # ``from_dict(parsed.to_dict())`` no longer reproducing what it was
            # given. Telling the two apart is what ``NoValue`` is for.
            value = self.__dict__.get(name, NoValue)
            if value is not NoValue:
                continue

            default = field.default
            if default is not NoValue:
                self.__dict__[name] = default
            else:
                # NOTE: Nothing to fill an unset field with, so the ``NoValue``
                # the generated ``__init__`` seeded it with is dropped rather than
                # kept: it is a *field* sentinel, not a value a schema may hold.
                # Dropping it rather than storing ``None`` also keeps the name out
                # of the context :meth:`pack` builds from ``__dict__``, which a
                # schema may be relying on to seed for itself -- the PCAP-NG
                # section header block reads its Byte-Order Magic from a ``match``
                # its own :meth:`pre_pack` supplies, and only when the context
                # does not name one already. :meth:`pack` reads an absent field as
                # ``None`` regardless.
                self.__dict__.pop(name, None)

        # NOTE: Packed here only when a packet context was actually handed over.
        # A schema is not in general packable from its own fields alone: a field
        # callback may read a key that the *enclosing* layer owns, as the
        # Multipath TCP options do with the ``length`` of the TCP option that
        # carries them, and packing without it raises rather than producing
        # octets. ``__updated__`` is still set, so a schema left unpacked here is
        # packed by :meth:`__bytes__` on first use -- by which time the enclosing
        # layer has supplied the context, which is where the octets were produced
        # before this method ran on construction at all.
        if packet is not None:
            self.pack(packet)

    def __update__(self, dict_: 'Optional[Mapping[str, _VT] | Iterable[tuple[str, _VT]]]' = None,
                   **kwargs: '_VT') -> 'None':
        # NOTE: Keys with the same names as the class's builtin methods will be
        # renamed with the class name prefixed as mangled class variables
        # implicitly and internally. Such mapping information will be stored
        # within: attr: `__map__` attribute.

        __name__ = type(self).__name__  # pylint: disable=redefined-builtin

        if dict_ is None:
            data_iter = kwargs.items()  # type: Iterable[tuple[str, Any]]
        elif isinstance(dict_, collections.abc.Mapping):
            data_iter = itertools.chain(dict_.items(), kwargs.items())
        else:
            data_iter = itertools.chain(dict_, kwargs.items())

        for (key, value) in data_iter:
            if key not in self.__buffer__:
                warn(f'{key!r} is not a valid field name', UnknownFieldWarning)
                continue

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

        self.__updated__ = True

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
            if isinstance(value, Schema):
                temp.append(f'{out_key}={type(value).__name__}(...)')
            else:
                temp.append(f'{out_key}={value!r}')
        args = ', '.join(temp)
        return f'{type(self).__name__}({args})'

    def __bytes__(self) -> 'bytes':
        if self.__updated__:
            self.pack()

        buffer = []  # type: list[bytes]
        for name in self.__fields__.keys():
            value = self.__buffer__[name]
            buffer.append(value)
        return b''.join(buffer)

    def __len__(self) -> 'int':
        return len(self.__bytes__())

    def __iter__(self) -> 'Iterator[str]':
        for key in self.__dict__:
            if key in self.__builtin__:
                continue
            yield self.__map_reverse__.get(key, key)

    def __getitem__(self, name: 'str') -> '_VT':
        if name in self.__fields__:
            key = self.__map__.get(name, name)
            return self.__dict__[key]
        return super().__getitem__(name)

    def __setattr__(self, name: 'str', value: '_VT') -> 'None':
        if name in self.__fields__:
            key = self.__map__.get(name, name)
            self.__dict__[key] = value
            # NOTE: ``self.__updated__ = True`` would re-enter this method once
            # per field assigned -- 180297 recursive calls per extraction of
            # examples/captures/http.pcap -- only to miss the __fields__ test and
            # fall through to object.__setattr__. ``__updated__`` is an instance
            # attribute established in __new__, so the direct store is the same
            # write with none of the round trip.
            self.__dict__['__updated__'] = True
            return
        return super().__setattr__(name, value)

    def __delattr__(self, name: 'str') -> 'None':
        if name in self.__fields__:
            key = self.__map__.get(name, name)
            del self.__dict__[key]
            self.__updated__ = True
            return
        return super().__delattr__(name)

    @classmethod
    def from_dict(cls, dict_: 'Optional[Mapping[str, _VT] | Iterable[tuple[str, _VT]]]' = None,
                  **kwargs: '_VT') -> 'Self':
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
        self.__post_init__()
        return self

    def to_dict(self) -> 'dict[str, _VT]':
        """Convert :class:`Schema` into :obj:`dict`.

        Important:
            We only convert nested :class:`Schema` objects into :obj:`dict` if
            they are the direct value of the :class:`Schema` object's attribute.
            Should such :class:`Schema` objects be nested within other data,
            types, such as :obj:`list`, :obj:`tuple`, :obj:`set`, etc., we
            shall not convert them into :obj:`dict` and remain them intact.

        """
        dict_ = {}  # type: dict[str, Any]
        for (key, value) in self.__dict__.items():
            if key in self.__excluded__:
                continue

            out_key = self.__map_reverse__.get(key, key)
            if isinstance(value, Schema):
                dict_[out_key] = value.to_dict()
            else:
                dict_[out_key] = value
        return dict_

    def to_bytes(self) -> 'bytes':
        """Convert :class:`Schema` into :obj:`bytes`."""
        return self.__bytes__()

    def get_payload(self, name: 'Optional[str]' = None) -> 'bytes':
        """Get payload of :class:`Schema`.

        Args:
            name: Name of the payload field.

        Returns:
            Payload of :class:`Schema` as :obj:`bytes`.

        """
        if name is None:
            name = self.__payload__

        field = self.__fields__.get(name)
        if field is None:
            raise ProtocolUnbound(f'unknown field: {name!r}')
        if not isinstance(field, PayloadField):
            raise ProtocolUnbound(f'not a payload field: {name!r}')
        return self.__buffer__[name]

    def pack(self, packet: 'Optional[dict[str, Any]]' = None) -> 'bytes':
        """Pack :class:`Schema` into :obj:`bytes`.

        Args:
            packet: Packet data.

        Returns:
            Packed :class:`Schema` as :obj:`bytes`.

        Notes:
            Since we do not know the length of the packet, we use a
            reasonable default value ``-1`` for the ``__length__``
            field, as the :class:`~pcapkit.corekit.fields.field.Field`
            class will consider negative value as a placeholder.

            If you want to pack the packet with the correct length,
            please provide the ``__length__`` value before packing.

        """
        if packet is None:
            packet = {}

        packet.update(self.__dict__)
        # NOTE: ``pre_unpack`` is called here as well as from the unpacking path
        # since a schema may seed ``packet`` keys that both paths need, as
        # ``pcapkit.protocols.schema.internet.hip.EncryptedParameter`` does.
        # ``pre_pack`` is what carries the packing-only preparation, such as the
        # PCAP-NG section header block's byte order magic, which no field of the
        # schema holds and which therefore cannot be recovered from
        # ``self.__dict__`` above.
        self.pre_unpack(packet)
        self.pre_pack(packet)

        if '__length__' not in packet:
            packet['__length__'] = -1  # reasonable default value

        for field in self.__fields__.values():
            field = field(packet)

            # NOTE: Read from the instance rather than with :func:`getattr`, which
            # finds the *class* attribute when the instance has none -- and a
            # schema's class attribute for a field is the
            # :class:`~pcapkit.corekit.fields.field.FieldBase` object itself. A
            # field the caller never set therefore arrived below as the field
            # rather than as a value: ``getattr(self, name, None)`` could not
            # return its ``None`` for one, so the absent-value branches never
            # fired, and what surfaced instead was a failure from inside the
            # packing of a field object -- naming a field *class*, and so saying
            # nothing about which field had been left out. See #422.
            data = self.__dict__.get(self.__map__.get(field.name, field.name))

            if isinstance(field, PayloadField):
                # NOTE: ``ProtocolBase``, not ``Protocol``. The two were one class
                # until the metaclass revision split them, which renamed the base to
                # ``ProtocolBase`` and kept ``Protocol`` as a thin subclass that adds
                # auto-registration for externally defined engines. Every module under
                # ``pcapkit.protocols.schema`` was updated to import the base under the
                # old name; this one was missed, because its import is a runtime import
                # inside a method rather than a ``TYPE_CHECKING`` one at module level.
                # No protocol in the library subclasses ``Protocol``, so the branch
                # below had been unreachable ever since: handing a payload field any
                # protocol instance -- which is exactly what :meth:`ProtocolBase._make_payload
                # <pcapkit.protocols.protocol.ProtocolBase._make_payload>` returns, and
                # what ``make``'s own ``bytes | Protocol | Schema`` signature advertises
                # -- fell through to the ``ProtocolUnbound`` below instead of being
                # packed. That is what stopped ``from_data`` reconstructing any parsed
                # packet. An external ``Protocol`` subclass is still a ``ProtocolBase``,
                # so nothing that worked before is affected. See #506.
                from pcapkit.protocols.protocol import \
                    ProtocolBase  # pylint: disable=import-outside-toplevel

                if data is None:
                    self.__buffer__[field.name] = b''
                elif isinstance(data, ProtocolBase):
                    self.__buffer__[field.name] = bytes(data)
                elif isinstance(data, bytes):
                    self.__buffer__[field.name] = data
                elif isinstance(data, Schema):
                    self.__buffer__[field.name] = data.pack(packet)
                else:
                    raise ProtocolUnbound(f'unsupported type {type(data)}')
                continue

            if isinstance(field, ListField):
                if data is None:
                    self.__buffer__[field.name] = b''
                elif isinstance(data, bytes):
                    self.__buffer__[field.name] = data
                elif isinstance(data, (list, tuple)):
                    # NOTE: a data model may declare a field ``tuple[...]``
                    # rather than ``list[...]`` -- e.g. HIP's ``group_id:
                    # 'tuple[Group, ...]'`` in pcapkit/protocols/data/internet/
                    # hip.py -- and ``_read_*`` then hands one straight back
                    # here on reconstruction. ``ListField.pack`` only ever
                    # iterates its argument, so it does not care which of the
                    # two it gets; rejecting the tuple broke every
                    # parse-then-reconstruct cycle for such a field. See #476.
                    # ``list(data)`` is a no-op for an actual list and keeps
                    # ``ListField.pack``'s own ``Optional[list[_TL]]``
                    # signature honest rather than widening it too.
                    self.__buffer__[field.name] = field.pack(list(data), packet)
                else:
                    raise ProtocolUnbound(f'unsupported type {type(data)}')
                continue

            if isinstance(field, PaddingField):
                self.__buffer__[field.name] = bytes(field.length)
                continue

            if isinstance(field, ConditionalField):
                if not field.test(packet):
                    self.__buffer__[field.name] = b''
                    continue
                field = field.field(packet)

            if isinstance(field, ForwardMatchField):
                # NOTE: a forward match consumes nothing, so it contributes no
                # octets to ``bytes(self)``/``len(self)`` either. :meth:`unpack`
                # mirrors this for the same reason -- see the ``ForwardMatchField``
                # branch there. See #446.
                self.__buffer__[field.name] = b''
                continue

            try:
                temp = field.pack(data, packet)
            except NoDefaultValue:
                temp = bytes(field.length)
            self.__buffer__[field.name] = temp

        self.post_process(packet)
        self.__updated__ = False
        return self.__bytes__()

    def pre_pack(self, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for packing process.

        Args:
            packet: packet data

        Note:
            This method is expected to directly modify any data stored
            in the ``packet`` and thus no return is required.

        """

    @classmethod
    @prepare
    def unpack(cls, data: 'bytes | IO[bytes]',
               length: 'Optional[int]' = None,
               packet: 'Optional[dict[str, Any]]' = None) -> 'Self':
        """Unpack :obj:`bytes` into :class:`Schema`.

        Args:
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Unpacked data as :class:`Schema`.

        Notes:
            We used a ``__length__`` key in ``packet`` to record the length
            of the remaining data, which is used to determine the length of
            the payload field.

            When this schema is nested -- unpacked through a
            :class:`~pcapkit.corekit.fields.misc.SchemaField` rather than
            directly -- ``packet`` is not the enclosing schema's own data, but
            a context built by :func:`~pcapkit.corekit.fields.misc.
            nested_packet_context`: a name this schema does not itself
            declare falls through to the enclosing schema, and the enclosing
            schema is also reachable unconditionally under a ``__packet__``
            key. See that function for the exact lookup, write and iteration
            semantics.

            And an ``__option_padding__`` key in the ``packet`` to record how
            much of an
            :class:`~pcapkit.corekit.fields.collections.OptionField`'s declared
            area it did not consume. What follows that area decides what the
            remainder means: usually padding, to be skipped, but a schema may
            equally read it as further options, as the PCAP-NG name resolution
            block does with its records and options.

            An :class:`~pcapkit.corekit.fields.collections.OptionField`
            declares the size of the whole area it may read, but stops at the
            end-of-option-list marker and reports the unconsumed remainder
            through ``__option_padding__``. Since that remainder has not been
            parsed, we rewind ``data`` by it, so that the fields which size
            themselves from ``__option_padding__`` read the remainder itself
            rather than the same number of octets from beyond it.

        """
        # force cast arg type since decorator changed their signatures
        if TYPE_CHECKING:
            data = cast('IO[bytes]', data)
            length = cast('int', length)
            packet = cast('dict[str, Any]', packet)

        self = cls.__new__(cls)
        for field in self.__fields__.values():
            field = field(packet)

            # NOTE: ``Field.length`` recomputes struct.calcsize() on every read,
            # so it is read once per field here rather than at each use.
            if isinstance(field, PayloadField):
                length = field.length
                payload_length = length or cast('int', packet['__length__'])

                payload = data.read(payload_length)
                self.__buffer__[field.name] = payload

                packet['__length__'] -= length
                packet[field.name] = payload

                setattr(self, field.name, payload)
                continue

            if isinstance(field, PaddingField):
                length = field.length

                byte = data.read(length)
                self.__buffer__[field.name] = byte

                packet[field.name] = byte
                packet['__length__'] -= length

                setattr(self, field.name, byte)
                continue

            if isinstance(field, ConditionalField):
                if not field.test(packet):
                    self.__buffer__[field.name] = b''
                    setattr(self, field.name, None)
                    packet[field.name] = NoValue
                    continue
                field = field.field(packet)

            length = field.length

            byte = data.read(length)
            self.__buffer__[field.name] = byte

            value = field.unpack(byte, packet.copy())
            setattr(self, field.name, value)

            packet[field.name] = value

            if isinstance(field, OptionField):
                packet['__option_padding__'] = field.option_padding

            if isinstance(field, ForwardMatchField):
                # NOTE: a forward match reads ``length`` octets so a later field
                # can size itself from them, but consumes neither the stream
                # (the rewind below) nor ``__length__`` (no decrement in this
                # branch). ``self.__buffer__[field.name]`` above still holds the
                # octets just read, though, and until here nothing undid that:
                # ``__bytes__``/``__len__`` concatenate every slot in
                # ``__buffer__``, so the schema over-reported its length by
                # exactly the forward match's width -- the same octets are read
                # again, for real, by whichever field actually needs them, so
                # nothing is lost by dropping the duplicate here. ``pack()``
                # above already zeroes this slot for the same field type;
                # zeroing it here as well is what makes a declared area checked
                # against ``len(self)`` -- :class:`~pcapkit.corekit.fields.collections.OptionField`
                # and :class:`~pcapkit.corekit.fields.collections.ListField` both
                # do this -- see the octets actually consumed. See #446.
                data.seek(-length, io.SEEK_CUR)
                self.__buffer__[field.name] = b''
            elif isinstance(field, OptionField) and field.option_padding > 0:
                # the option list ended before the declared field length was
                # exhausted; give the unconsumed remainder back to ``data``
                # so that the following fields can read it
                data.seek(-field.option_padding, io.SEEK_CUR)
                consumed = length - field.option_padding

                self.__buffer__[field.name] = byte[:consumed]
                packet['__length__'] -= consumed
            else:
                packet['__length__'] -= length

            if packet['__length__'] < 0:
                warn(f'packet length < 0: {packet["__length__"]}',
                     SchemaWarning, stacklevel=stacklevel())

        self.__updated__ = False
        return self

    @classmethod
    def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for unpacking process.

        Args:
            packet: packet data

        Note:
            This method is expected to directly modify any data stored
            in the ``packet`` and thus no return is required.

        """

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after packing and/or unpacking process.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        return self


class _EnumRegistry(collections.defaultdict):
    """A registry :class:`collections.defaultdict` that never inserts a miss.

    :attr:`EnumSchema.registry` (and its class-level twin,
    :attr:`EnumMeta.registry`) is read with a bare ``registry[code]`` at dozens
    of call sites across the schema layer, e.g. ``Option.registry[type]``. A
    plain :class:`collections.defaultdict` inserts whatever
    :attr:`~collections.defaultdict.default_factory` returns the *first time*
    an unregistered ``code`` is looked up -- and since the registry lives on
    the *class*, that insertion is permanent and shared by every instance of
    every subclass in the process. Parsing one packet carrying an unrecognised
    code is therefore enough to grow the registry for the remainder of the
    process, and to make a later, entirely legitimate
    :meth:`EnumSchema.register` call report an overwrite that never happened.

    This is the schema-layer instance of the defect :meth:`ProtocolBase.\
    _lookup_registry <pcapkit.protocols.protocol.ProtocolBase._lookup_registry>`
    fixed for the protocol-layer ``__proto__`` family in GitHub issues #421 and
    #425/#428; see GitHub issue #555. The fallback itself is deliberate -- it
    is how an unknown option, chunk or block falls back to its
    ``Unknown*``/``Unassigned*`` schema -- so this subclass keeps returning it,
    it just stops recording it.

    """

    def __missing__(self, key: 'Any') -> 'Any':
        if self.default_factory is None:
            raise KeyError(key)
        return self.default_factory()


class EnumMeta(SchemaMeta, Generic[_ET]):
    """Meta class to add dynamic support for :class:`EnumSchema`.

    This meta class is used to generate necessary attributes for the
    :class:`SchemaMeta` class. It can be useful to reduce runtime generation
    cost as well as caching already generated attributes.

    * :attr:`~EnumSchema.registry` is added to subclasses as an *immutable*
      proxy (similar to :class:`property`, but on class variables) to the
      :attr:`EnumSchema.__enum__` mapping.

    """

    if TYPE_CHECKING:
        #: Mapping of enumeration numbers to schemas (**internal use only**).
        __enum__: 'DefaultDict[_ET, Type[EnumSchema]]'

    @property
    def registry(cls) -> 'DefaultDict[_ET, Type[EnumSchema]]':
        """Mapping of enumeration numbers to schemas.

        Important:
            The returned mapping is a :class:`_EnumRegistry`, not a plain
            :class:`collections.defaultdict`: indexing it with an
            unregistered ``code`` still returns :attr:`EnumSchema.__default__`'s
            schema, but does **not** insert that code. See :class:`_EnumRegistry`
            for why that distinction matters.

        """
        return cls.__enum__


class EnumSchema(Schema, Generic[_ET], metaclass=EnumMeta):
    """:class:`Schema` with enumeration mapping support.

    Examples:

        To create an enumeration mapping supported schema, simply

        .. code-block:: python

           class MySchema(EnumSchema[MyEnum]):

               # optional, set the default schema for enumeration mapping
               # if the enumeration number is not found in the mapping
               __default__ = lambda: UnknownSchema  # by default, None

        then, you can use inheritance to create a list of schemas
        for this given enumeration mapping:

        .. code-block:: python

           class OneSchema(MySchema, code=MyEnum.ONE):
               ...

           class MultipleSchema(MySchema, code=[MyEnum.TWO, MyEnum.THREE]):
               ...

        or optionally, using the :meth:`register` method to register a
        schema to the enumeration mapping:

        .. code-block:: python

           MySchema.register(MyEnum.ZERO, ZeroSchema)

        And now you can access the enumeration mapping via the :attr:`registry`
        property (more specifically, class attribute):

        .. code-block:: python

           >>> MySchema.registry[MyEnum.ONE]  # OneSchema

    """

    __additional__ = ['__enum__', '__default__']
    __excluded__ = ['__enum__', '__default__']

    #: Callback to return the default schema for enumeration mapping,
    #: by default is a ``lambda: None`` statement.
    __default__: 'Callable[[], Type[Self]]' = lambda: None  # type: ignore[assignment,return-value]

    if TYPE_CHECKING:
        #: Mapping of enumeration numbers to schemas.
        __enum__: 'DefaultDict[_ET, Type[Self]]'

    @property
    def registry(self) -> 'DefaultDict[_ET, Type[Self]]':
        """Mapping of enumeration numbers to schemas.

        Note:
            This property is also available as a class
            attribute.

        Important:
            See :attr:`EnumMeta.registry`: the returned mapping is a
            :class:`_EnumRegistry`, so looking up an unregistered ``code``
            returns the default schema without recording ``code`` as if it
            had been registered.

        """
        return self.__enum__

    def __init_subclass__(cls, /, code: 'Optional[_ET | Iterable[_ET]]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Register enumeration to :attr:`registry` mapping.

        Args:
            code: Enumeration code. It can be either a single enumeration
                or a list of enumerations.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        If ``code`` is provided, the subclass will be registered to the
        :attr:`registry` mapping with the given ``code``. If ``code`` is
        not given, the subclass will not be registered.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If any of ``code`` is
                already registered, naming the displaced schema and its
                replacement. This is the same guard :meth:`register` applies,
                and it is here as well because a class declaration is the
                *other* way into :attr:`__enum__` -- ``class MyOption(Option,
                code=...)`` writes the registry without any call to
                :meth:`register`, so guarding only the method would leave the
                declaration path silently displacing a built-in schema.

        Notes:
            If :attr:`__enum__` is not yet defined at function call,
            it will automatically be defined as a :class:`_EnumRegistry`
            object, with the default value set to :attr:`__default__`.

            If intended to customise the :attr:`__enum__` mapping,
            it is possible to override the :meth:`__init_subclass__` method and
            define :attr:`__enum__` manually. Such a manual definition may use
            a plain :class:`collections.defaultdict` -- e.g. to seed a
            namespaced or nested mapping such as
            :class:`pcapkit.protocols.schema.misc.pcapng.Option`'s -- so it is
            swapped for the retention-safe :class:`_EnumRegistry` below, before
            anything else can hold a reference to the original object.

        """
        # NOTE: the base hook goes first, before any of the registry work below.
        # :meth:`Schema.__init_subclass__` is what refuses to derive from a
        # finalised schema, and a refusal has to land before this method writes
        # ``cls`` into ``__enum__``: raising afterwards would discard the class
        # object while leaving the registry pointing at it, so a rejected
        # declaration would still have displaced a built-in schema. It took no
        # arguments when it was the last statement here and still takes none --
        # ``code`` is this method's own and the rest are deliberately dropped.
        super().__init_subclass__()

        if not hasattr(cls, '__enum__'):
            cls.__enum__ = _EnumRegistry(cls.__default__)
        elif '__enum__' in cls.__dict__ and not isinstance(cls.__dict__['__enum__'], _EnumRegistry):
            # ``cls`` set its own ``__enum__`` in the class body, as a plain
            # ``collections.defaultdict`` -- swap it for the retention-safe
            # variant now, while ``cls`` is still being constructed and no
            # external code has had a chance to capture a reference to the
            # original dict. Every later access, through :attr:`registry` or
            # otherwise, then sees the same safe object -- so identity across
            # repeated ``.registry`` reads (see ``EnumMeta.registry``) is
            # preserved, and nothing but the retention behaviour changes.
            manual = cls.__dict__['__enum__']
            cls.__enum__ = _EnumRegistry(getattr(manual, 'default_factory', None), manual)

        if code is not None:
            # One loop over both shapes, so the overwrite guard below is written
            # once rather than once per branch. ``register`` cannot be delegated
            # to here: :class:`pcapkit.protocols.schema.misc.pcapng.Option`
            # overrides it with an incompatible signature, so ``cls.register``
            # does not mean the same thing for every subclass.
            codes = code if isinstance(code, collections.abc.Iterable) else (code,)
            for _code in codes:
                # This loop visits every element of an iterable ``code``, so a
                # repeated member -- or two members that are the same object,
                # as an :class:`enum.Enum` alias makes possible -- reaches this
                # twice for the same key with ``cls`` on both sides: incumbent
                # on the first pass, replacement on the second. So ordinary
                # subclassing syntax reaches this guard, e.g.
                # ``class X(Base, code=[A, A])`` or ``code=[A, B]`` with
                # ``A is B``, with no second call to this method needed.
                incumbent = cls.__enum__.get(_code)  # type: ignore[arg-type]
                if incumbent is not None and incumbent is not cls:
                    warn(f'schema {_code} already registered, overwriting '
                         f'{incumbent!r} with {cls!r}', RegistryWarning)
                cls.__enum__[_code] = (cls)  # type: ignore[index]

    @classmethod
    def register(cls, code: '_ET', schema: 'Type[Self]') -> 'None':
        """Register enumetaion to :attr:`__enum__` mapping.

        Args:
            code: Enumetaion code.
            schema: Enumetaion schema.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If ``code`` is already
                registered, naming the displaced schema and its replacement.

        Note:
            Every public registrar in
            :mod:`pcapkit.foundation.registry.protocols` that accepts a
            ``schema`` registers two halves of one binding -- a parser class
            through e.g. :meth:`IPv4.register_option
            <pcapkit.protocols.internet.ipv4.IPv4.register_option>`, and a
            schema class through this method. The parser half has warned on an
            overwrite for as long as it has existed; this half assigned bare, so
            one ``register_ipv4_option`` call replacing a built-in reported the
            parser it displaced and said nothing about the schema. The guard
            here closes that asymmetry.

            It fires only when the incumbent differs from the replacement, the
            same guard :func:`register_protocol
            <pcapkit.foundation.registry.protocols.register_protocol>` applies,
            even though ``code`` here -- unlike ``register_protocol``'s key --
            is supplied by the caller and independent of ``schema``. GitHub
            issue #718 corrected the previous presence-only guard: a repeat
            call that names the exact same schema object is a caller replaying
            a registration, not a mistake, so it is now a silent no-op.

            Presence is a faithful "was this really registered" test only because
            :class:`_EnumRegistry` returns a miss without recording it. A plain
            :class:`collections.defaultdict` would have inserted
            :attr:`__default__` the first time any unregistered ``code`` was
            looked up, so parsing a single packet carrying an unknown code would
            have made the next legitimate registration for that code warn about
            an entry no caller ever asked for -- the defect fixed for this layer
            in #555, and for the parser-layer ``__proto__`` family in #421 and
            #425/#428. That fix is what makes this guard safe to add.

            :class:`pcapkit.protocols.schema.misc.pcapng.Option` overrides this
            method with a namespaced registry of its own and does not delegate
            here, so it is guarded separately.

        """
        incumbent = cls.__enum__.get(code)  # type: ignore[arg-type]
        if incumbent is not None and incumbent is not schema:
            warn(f'schema {code} already registered, overwriting '
                 f'{incumbent!r} with {schema!r}', RegistryWarning)

        cls.__enum__[code] = schema  # type: ignore[index]
