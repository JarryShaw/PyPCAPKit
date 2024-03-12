# -*- coding: utf-8 -*-
"""schema for protocol headers"""

import abc
import collections
import collections.abc
import io
import itertools
import sys
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast, final

from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.field import FieldBase, NoValue
from pcapkit.corekit.fields.misc import ConditionalField, ForwardMatchField, PayloadField
from pcapkit.corekit.fields.strings import PaddingField
from pcapkit.corekit.infoclass import FinalisedState
from pcapkit.utilities.compat import Mapping
from pcapkit.utilities.decorators import prepare
from pcapkit.utilities.exceptions import NoDefaultValue, ProtocolUnbound, stacklevel
from pcapkit.utilities.warnings import SchemaWarning, UnknownFieldWarning, warn

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
        The decorator should only be used on the *final*
        class, otherwise, any subclasses derived from a
        finalised schema class will not be re-finalised.

    Args:
        cls: Schema class.
        _finalised: Whether to make the schema class finalised.

    Returns:
        Finalised schema class.

    :meta decorator:
    """
    if cls.__finalised__ == FinalisedState.FINAL:
        warn(f'{cls.__name__}: schema has been finalised; now skipping',
             SchemaWarning, stacklevel=stacklevel())
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

    # NOTE: We shall only attempt to generate ``__init__`` method
    # if the class does not define such method.
    if not hasattr(cls, '__init__'):
        # NOTE: We only generate typed ``__init__`` method if only the class
        # has field definition from any of itself and its base classes.
        if args_:
            # NOTE: The following code is to make the ``__init__`` method work.
            # It is inspired from the :func:`dataclasses._create_fn` function.
            init_ = (
                f'def __create_fn__():\n'
                f'    def __init__(self, {", ".join(args_)}, *, __packet__=None):\n'
                f'        self.__update__({", ".join(dict_)})\n'
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
        cls.__finalised__ = FinalisedState.BASE
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

    def __new__(cls, name: 'str', bases: 'tuple[type, ...]', attrs: 'dict[str, Any]', **kwargs: 'Any') -> 'Type[Schema]':
        """Create the schema class.

        Args:
            name: Schema class name.
            bases: Schema class bases.
            attrs: Schema class attributes.
            **kwargs: Arbitrary keyword arguments in class definition.

        This method is used to inherit the :attr:`~Schema.__additional__` and
        :attr:`~Schema.__excluded__` fields from the base classes, as well as
        populating both fields from the subclass attributes.

        """
        if '__additional__' not in attrs:
            attrs['__additional__'] = []
        if '__excluded__' not in attrs:
            attrs['__excluded__'] = []

        for base in bases:
            if hasattr(base, '__additional__'):
                attrs['__additional__'].extend(name for name in base.__additional__ if name not in attrs['__additional__'])
            if hasattr(base, '__excluded__'):
                attrs['__excluded__'].extend(name for name in base.__excluded__ if name not in attrs['__excluded__'])

        # NOTE: for unknown reason, the following code will cause an error
        # for duplicated keyword arguments in class definition.
        if sys.version_info < (3, 11):
            return type.__new__(cls, name, bases, attrs, **kwargs)
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

    def __new__(cls, *args: '_VT', **kwargs: '_VT') -> 'Self':  # pylint: disable=unused-argument
        """Create a new instance.

        The class will try to automatically generate ``__init__`` method with
        the same signature as specified in class variables' type annotations,
        which is inspired by :pep:`557` (:mod:`dataclasses`).

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        """
        if cls.__finalised__ == FinalisedState.NONE:
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
        for name, field in self.__fields__.items():
            if self.__dict__[name] in (NoValue, None):
                self.__dict__[name] = field.default
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
            self.__updated__ = True
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
        self.pre_unpack(packet)

        if '__length__' not in packet:
            packet['__length__'] = -1  # reasonable default value

        for field in self.__fields__.values():
            field = field(packet)

            if isinstance(field, PayloadField):
                from pcapkit.protocols.protocol import \
                    Protocol  # pylint: disable=import-outside-toplevel

                data = getattr(self, field.name, None)
                if data is None:
                    self.__buffer__[field.name] = b''
                elif isinstance(data, Protocol):
                    self.__buffer__[field.name] = bytes(data)
                elif isinstance(data, bytes):
                    self.__buffer__[field.name] = data
                elif isinstance(data, Schema):
                    self.__buffer__[field.name] = data.pack(packet)
                else:
                    raise ProtocolUnbound(f'unsupported type {type(data)}')
                continue

            if isinstance(field, ListField):
                data = getattr(self, field.name, None)
                if data is None:
                    self.__buffer__[field.name] = b''
                elif isinstance(data, bytes):
                    self.__buffer__[field.name] = data
                elif isinstance(data, list):
                    self.__buffer__[field.name] = field.pack(data, packet)
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
                self.__buffer__[field.name] = b''
                continue

            value = getattr(self, field.name)
            try:
                temp = field.pack(value, packet)
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

            And a ``__padding_length__`` key in the ``packet`` to record the
            length of the padding field after an
            :class:`~pcapkit.corekit.fields.collections.OptionField`, which
            is used to potentially determine the length of the remaining
            padding field data.

        """
        # force cast arg type since decorator changed their signatures
        if TYPE_CHECKING:
            data = cast('IO[bytes]', data)
            length = cast('int', length)
            packet = cast('dict[str, Any]', packet)

        self = cls.__new__(cls)
        for field in self.__fields__.values():
            field = field(packet)

            if isinstance(field, PayloadField):
                payload_length = field.length or cast('int', packet['__length__'])

                payload = data.read(payload_length)
                self.__buffer__[field.name] = payload

                packet['__length__'] -= field.length
                packet[field.name] = payload

                setattr(self, field.name, payload)
                continue

            if isinstance(field, PaddingField):
                byte = data.read(field.length)
                self.__buffer__[field.name] = byte

                packet[field.name] = byte
                packet['__length__'] -= field.length

                setattr(self, field.name, byte)
                continue

            if isinstance(field, ConditionalField):
                if not field.test(packet):
                    self.__buffer__[field.name] = b''
                    setattr(self, field.name, None)
                    packet[field.name] = NoValue
                    continue
                field = field.field(packet)

            byte = data.read(field.length)
            self.__buffer__[field.name] = byte

            value = field.unpack(byte, packet.copy())
            setattr(self, field.name, value)

            packet[field.name] = value

            if isinstance(field, OptionField):
                packet['__option_padding__'] = field.option_padding

            if isinstance(field, ForwardMatchField):
                data.seek(-field.length, io.SEEK_CUR)
            else:
                packet['__length__'] -= field.length

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
        """Mapping of enumeration numbers to schemas."""
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

        Notes:
            If :attr:`__enum__` is not yet defined at function call,
            it will automatically be defined as a :class:`collections.defaultdict`
            object, with the default value set to :attr:`__default__`.

            If intended to customise the :attr:`__enum__` mapping,
            it is possible to override the :meth:`__init_subclass__` method and
            define :attr:`__enum__` manually.

        """
        if not hasattr(cls, '__enum__'):
            cls.__enum__ = collections.defaultdict(cls.__default__)

        if code is not None:
            if isinstance(code, collections.abc.Iterable):
                for _code in code:
                    cls.__enum__[_code] = (cls)  # type: ignore[index]
            else:
                cls.__enum__[code] = (cls)  # type: ignore[index]
        super().__init_subclass__()

    @classmethod
    def register(cls, code: '_ET', schema: 'Type[Self]') -> 'None':
        """Register enumetaion to :attr:`__enum__` mapping.

        Args:
            code: Enumetaion code.
            schema: Enumetaion schema.

        """
        cls.__enum__[code] = schema  # type: ignore[index]
