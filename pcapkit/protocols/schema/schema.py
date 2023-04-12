# -*- coding: utf-8 -*-
"""schema for protocol headers"""

import collections
import collections.abc
import functools
import io
import itertools
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.fields.collections import ListField
from pcapkit.corekit.fields.field import NoValue, _Field
from pcapkit.corekit.fields.misc import ConditionalField, ForwardMatchField, PayloadField
from pcapkit.corekit.fields.strings import PaddingField
from pcapkit.utilities.compat import Mapping
from pcapkit.utilities.decorators import prepare
from pcapkit.utilities.exceptions import NoDefaultValue, ProtocolUnbound
from pcapkit.utilities.warnings import UnknownFieldWarning, warn

if TYPE_CHECKING:
    from collections import OrderedDict
    from typing import IO, Any, Iterable, Iterator, Optional

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
        #: Mapping of fields.
        __fields__: 'OrderedDict[str, _Field]'
        #: Mapping of field names to packed values.
        __buffer__: 'dict[str, bytes]'
        #: Flag for whether the schema is recently updated.
        __updated__: 'bool'

    #: Field name of the payload.
    __payload__: 'str' = 'payload'
    #: List of additional built-in names.
    __additional__: 'list[str]' = []
    #: List of names to be excluded from :obj:`dict` conversion.
    __excluded__: 'list[str]' = []

    def __new__(cls, *args: 'VT', **kwargs: 'VT') -> 'Schema':  # pylint: disable=unused-argument
        """Create a new instance.

        The class will try to automatically generate ``__init__`` method with
        the same signature as specified in class variables' type annotations,
        which is inspired by :pep:`557` (:mod:`dataclasses`).

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        """
        cls_fields = []

        temp = ['__map__', '__map_reverse__', '__builtin__',
                '__fields__', '__buffer__', '__updated__',
                '__payload__']
        temp.extend(cls.__additional__)
        for obj in cls.mro():
            temp.extend(dir(obj))
        cls.__builtin__ = set(temp)
        cls.__excluded__.extend(cls.__builtin__)

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
                cls_fields.append((key, field))

        # NOTE: We reverse the two lists such that the order of the
        # arguments is the same as the order of the type annotations, i.e.,
        # from the most base class to the most derived class.
        args_.reverse()
        dict_.reverse()
        cls_fields.reverse()
        cls.__fields__ = collections.OrderedDict(cls_fields)

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

        # NOTE: We define the ``__map__`` and ``__map_reverse__`` attributes
        # here under ``self`` to avoid them being considered as class variables
        # and thus being shared by all instances.
        super().__setattr__(self, '__map__', {})
        super().__setattr__(self, '__map_reverse__', {})

        # NOTE: We only create the attributes for the instance itself,
        # to avoid creating shared attributes for the class.
        self.__buffer__ = {name: b'' for name in self.__fields__.keys()}
        self.__updated__ = True

        return self

    def __post_init__(self) -> 'None':
        for name, field in self.__fields__.items():
            if self.__dict__[name] in (NoValue, None):
                self.__dict__[name] = field.default
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

    def __getitem__(self, name: 'str') -> 'VT':
        if name in self.__fields__:
            key = self.__map__.get(name, name)
            return self.__dict__[key]
        return super().__getitem__(name)

    def __setattr__(self, name: 'str', value: 'VT') -> 'None':
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
        self.__post_init__()
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

        """
        if packet is None:
            packet = {}
        packet.update(self.__dict__)

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
                field = field.field

            if isinstance(field, ForwardMatchField):
                self.__buffer__[field.name] = b''
                continue

            value = getattr(self, field.name)
            try:
                temp = field.pack(value, self.__dict__)
            except NoDefaultValue:
                temp = bytes(field.length)
            self.__buffer__[field.name] = temp

        self.__updated__ = False
        return self.__bytes__()

    @classmethod
    @prepare
    def unpack(cls, data: 'bytes | IO[bytes]',
               length: 'Optional[int]' = None,
               packet: 'Optional[dict[str, Any]]' = None) -> 'Schema':
        """Unpack :obj:`bytes` into :class:`Schema`.

        Args:
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Unpacked data as :class:`Schema`.

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
                field = field.field

            byte = data.read(field.length)
            self.__buffer__[field.name] = byte

            value = field.unpack(byte, packet.copy())
            setattr(self, field.name, value)

            packet[field.name] = value

            if isinstance(field, ForwardMatchField):
                data.seek(-field.length, io.SEEK_CUR)
            else:
                packet['__length__'] -= field.length

        self.__updated__ = False
        return self

    @classmethod
    def pre_process(cls, packet: 'dict[str, Any]') -> 'None':
        """Prepare ``packet`` data for unpacking process.

        Args:
            packet: packet data

        Note:
            This method is expected to directly modify any data stored
            in the ``packet`` and thus no return is required.

        """

    @classmethod
    def post_process(cls, schema: 'Schema', data: 'IO[bytes]',
                     length: 'int', packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        Args:
            schema: parsed schema
            data: Packed data.
            length: Length of data.
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        return schema
