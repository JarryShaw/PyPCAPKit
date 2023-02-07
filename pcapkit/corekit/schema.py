# -*- coding: utf-8 -*-
"""schema for protocol headers"""

import collections.abc
import io
import itertools
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.fields.field import NoValue, _Field
from pcapkit.corekit.fields.misc import ConditionalField, PayloadField
from pcapkit.utilities.compat import Mapping
from pcapkit.utilities.exceptions import NoDefaultValue, ProtocolUnbound

if TYPE_CHECKING:
    from typing import IO, Any, Iterable, Iterator, Optional

    from pcapkit.corekit.fields.field import NoValueType

__all__ = ['Schema']

VT = TypeVar('VT')


class Schema(Mapping[str, VT], Generic[VT]):
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
        #: List of fields.
        __fields__: 'list[_Field]'
        #: Mapping of field names to packed values.
        __buffer__: 'dict[str, bytes | NoValueType]'
        #: Flag for whether the schema is recently updated.
        __updated__: 'bool'

    def __new__(cls, *args: 'VT', **kwargs: 'VT') -> 'Schema':  # pylint: disable=unused-argument
        """Create a new instance.

        The class will try to automatically generate ``__init__`` method with
        the same signature as specified in class variables' type annotations,
        which is inspired by :pep:`557` (:mod:`dataclasses`).

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        """
        cls.__map__ = {}
        cls.__map_reverse__ = {}

        temp = ['__map__', '__map_reverse__', '__builtin__',
                '__fields__', '__buffer__', 'pack', 'unpack']
        for obj in cls.mro():
            temp.extend(dir(obj))
        cls.__builtin__ = set(temp)

        args_ = []  # type: list[str]
        dict_ = []  # type: list[str]

        for cls_ in cls.mro():
            # NOTE: We skip the ``Schema`` class itself, to avoid superclass
            # type annotations being considered.
            if cls_ is Schema:
                break

            # NOTE: We iterate in reversed order to ensure that the type
            # annotations of the superclasses are considered first.
            for key in reversed(cls_.__dict__):
                # NOTE: We skip duplicated annotations to avoid duplicate
                # argument in function definition.
                if key in args_:
                    continue

                # NOTE: We only consider the fields that are instances of
                # the ``_Field`` class.
                field = cls_.__dict__[key]
                if not isinstance(field, _Field):
                    continue

                # NOTE: We need to consider the case where the field itself
                # is optional, i.e., the field is not required to be present
                # in the protocol header.
                args_.append(f'{key}=NoValue')
                dict_.append(f'{key}={key}')

                field.name = key
                cls.__fields__.append(field)

        # NOTE: We reverse the two lists such that the order of the
        # arguments is the same as the order of the type annotations, i.e.,
        # from the most base class to the most derived class.
        args_.reverse()
        dict_.reverse()
        cls.__fields__.reverse()

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
        cls.__init__ = ns['__create_fn__']()
        cls.__init__.__qualname__ = f'{cls.__name__}.__init__'

        self = super().__new__(cls)

        # NOTE: We only create the attributes for the instance itself,
        # to avoid creating shared attributes for the class.
        self.__buffer__ = {}
        self.__updated__ = False

        return self

    def __post_init__(self) -> 'None':
        for field in self.__fields__:
            if self.__dict__[field.name] is NoValue:
                self.__dict__[field.name] = field.default
        self.pack()

    def __update__(self, dict_: 'Optional[Mapping[str, VT] | Iterable[tuple[str, VT]]]' = None,
                   **kwargs: 'VT') -> 'None':
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
            out_key = self.__map_reverse__.get(key, key)
            temp.append(f'{out_key}={value}')
        args = ', '.join(temp)
        return f'{type(self).__name__}({args})'

    def __repr__(self) -> 'str':
        temp = []  # type: list[str]
        for (key, value) in self.__dict__.items():
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
        for field in self.__fields__:
            value = self.__dict__[field.name]
            if value is NoValue:
                value = field.default
                if value is NoValue:
                    value = bytes(field.length)
            buffer.append(value)
        return b''.join(buffer)

    def __len__(self) -> 'int':
        return len(self.__dict__)

    def __iter__(self) -> 'Iterator[str]':
        for key in self.__dict__:
            yield self.__map_reverse__.get(key, key)

    def __getitem__(self, name: 'str') -> 'VT':
        key = self.__map__.get(name, name)
        return self.__dict__[key]

    def __setattr__(self, name: 'str', value: 'VT') -> 'None':
        key = self.__map__.get(name, name)
        self.__dict__[key] = value
        self.__updated__ = True

    def __delattr__(self, name: 'str') -> 'None':
        key = self.__map__.get(name, name)
        del self.__dict__[key]
        self.__updated__ = True

    @classmethod
    def from_dict(cls, dict_: 'Optional[Mapping[str, VT] | Iterable[tuple[str, VT]]]' = None,
                  **kwargs: 'VT') -> 'Schema[VT]':
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
            out_key = self.__map_reverse__.get(key, key)
            if isinstance(value, Schema):
                dict_[out_key] = value.to_dict()
            else:
                dict_[out_key] = value
        return dict_

    def to_bytes(self) -> 'bytes':
        """Convert :class:`Schema` into :obj:`bytes`."""
        return self.__bytes__()

    def pack(self) -> 'None':
        """Pack :class:`Schema` into :obj:`bytes`."""
        buffer = self.__buffer__
        packet = self.__dict__

        for field in self.__fields__:
            if isinstance(field, PayloadField):
                from pcapkit.protocols.protocol import \
                    Protocol  # pylint: disable=import-outside-toplevel

                data = getattr(self, field.name, None)
                if data is None:
                    buffer[field.name] = b''
                elif isinstance(data, Protocol):
                    buffer[field.name] = bytes(data)
                elif isinstance(data, bytes):
                    buffer[field.name] = data
                elif isinstance(data, Schema):
                    buffer[field.name] = data.pack()
                else:
                    raise ProtocolUnbound(f'unsupported type {type(data)}')
                continue

            if isinstance(field, ConditionalField):
                if not field(packet).test(packet):
                    continue
                field = field.field

            value = getattr(self, field.name)
            try:
                temp = field(packet).pack(value, self.__dict__)  # type: bytes | NoValueType
            except NoDefaultValue:
                temp = NoValue
            buffer[field.name] = temp

        self.__updated__ = False

    @classmethod
    def unpack(cls, data: 'bytes | IO[bytes]') -> 'None':
        """Unpack :obj:`bytes` into :class:`Schema`.

        Args:
            data: Packed data.

        """
        self = cls.__new__(cls)

        if isinstance(data, bytes):
            length = len(data)
            data = io.BytesIO(data)
        else:
            current = data.tell()
            length = data.seek(0, io.SEEK_END) - current
            data.seek(current)

        packet = self.__dict__
        buffer = self.__buffer__

        for field in self.__fields__:
            if isinstance(field, PayloadField):
                payload_length = field.test_length(packet, length)
                payload = data.read(payload_length)

                buffer[field.name] = payload
                setattr(self, field.name, payload)
                continue

            if isinstance(field, ConditionalField):
                if not field(packet).test(packet):
                    continue
                field = field.field

            byte = data.read(field.length)
            buffer[field.name] = byte

            value = field(packet).unpack(byte, packet)
            setattr(self, field.name, value)
            length -= field.length

        self.__updated__ = False
