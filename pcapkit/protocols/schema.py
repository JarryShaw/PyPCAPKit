# -*- coding: utf-8 -*-
"""schema for protocol headers

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.schema.keep_short_read`` and
   ``pcapkit.protocols.schema.schema.replay_short_read``, now
   :func:`pcapkit.corekit.schema.shortread.keep_short_read` and
   :func:`pcapkit.corekit.schema.shortread.replay_short_read` (:issue:`2674`).

"""

import abc
import collections
import collections.abc
import io
import itertools
import sys
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

from pcapkit.corekit.decorators import prepare
from pcapkit.corekit.fields.collections import ListField, OptionField
from pcapkit.corekit.fields.field import FieldBase
from pcapkit.corekit.fields.misc import (ConditionalField, ForwardMatchField, PayloadField,
                                         SchemaField)
from pcapkit.corekit.fields.strings import PaddingField
from pcapkit.corekit.infoclass import FinalisedState
from pcapkit.corekit.sentinels import NO_VALUE
from pcapkit.utilities.compat import Mapping, final
from pcapkit.utilities.exceptions import NoDefaultValue, ProtocolUnbound, SchemaError, stacklevel
from pcapkit.utilities.pickle import ReduceAsProtocol2
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

    This decorator generates the attributes and methods of the decorated
    :class:`Schema` class once, rather than at runtime.

    Notes:
        Use it on the *final* class only. With ``_finalised=True`` it seals the
        class against *subclassing*, which :meth:`Schema.__init_subclass__`
        enforces, and marks it with :func:`~pcapkit.utilities.compat.final`, so
        ``@schema_final`` implies ``@final``; writing both is harmless.
        :meth:`Schema.__new__` refuses ``@final`` *without* this decorator,
        where ``@final`` is :func:`~pcapkit.utilities.compat.final`, or
        :func:`typing.final` on Python 3.11 and up. Below 3.11,
        :func:`typing.final` sets no ``__final__`` (gh-90500), so a class
        marked with it is not refused.

        Applying it to the same class a second time only warns, and the class
        comes back finalised and usable.

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

    .. versionchanged:: 1.5.0

       A class finalised with ``_finalised=True`` refuses to be subclassed,
       and a schema marked ``@final`` without this decorator cannot be
       instantiated (:issue:`778`).

    :meta decorator:
    """
    # NOTE: Keyed on ``__finalised__``, which only this function sets, and read from
    # ``cls.__dict__``, since it is inherited; as in ``info_final``.
    if cls.__dict__.get('__finalised__') == FinalisedState.FINAL:
        warn(f'{cls.__name__}: schema has been finalised; now skipping',
             SchemaWarning, stacklevel=stacklevel())
        return cls

    # NOTE: ``Schema`` never reaches ``FinalisedState.BASE``, so without its own
    # ``__base_ready__`` marker every bare ``Schema()`` would redo the scan below.
    if cls is Schema and cls.__dict__.get('__base_ready__'):
        return cls

    temp = ['__map__', '__map_reverse__', '__builtin__',
            '__fields__', '__buffer__', '__updated__',
            '__payload__', '__finalised__', '__remainder__', '__remainder_offset__',
            '__short_read__']
    temp.extend(cls.__additional__)
    for obj in cls.mro():
        temp.extend(el for el in dir(obj) if el not in cls.__fields__)
    cls.__builtin__ = set(temp)
    cls.__excluded__.extend(cls.__builtin__)

    args_ = [f'{key}=NO_VALUE' for key in cls.__fields__]
    dict_ = [f'{key}={key}' for key in cls.__fields__]

    # NOTE: Only where the class defines none, as ``NoPayload`` does (``hasattr`` is always true);
    # without one, ``Schema(...)`` skips ``__post_init__``, leaving omitted fields as field objects.
    if '__init__' not in cls.__dict__:
        # NOTE: A typed ``__init__`` only for a class with fields, own or inherited.
        if args_:
            # NOTE: After ``dataclasses._create_fn``. ``**kwargs`` reaches ``__update__``, which
            # warns of a non-field; the MPTCP options take ``kind``/``length`` that way on purpose.
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
        # NOTE: Never ``BASE`` on ``Schema`` itself, as for ``Info`` (see ``info_final``):
        # subclasses would inherit it and skip the bare-``@final`` guard of ``Schema.__new__``.
        if cls is not Schema:
            cls.__finalised__ = FinalisedState.BASE
        else:
            cls.__base_ready__ = True
        return cls

    cls.__finalised__ = FinalisedState.FINAL
    return final(cls)


class SchemaMeta(abc.ABCMeta):
    """Meta class to add dynamic support to :class:`Schema`.

    It generates the attributes of the :class:`Schema` class:

    * :attr:`Schema.__fields__` maps each field name, the attribute name, to
      its :class:`~pcapkit.corekit.fields.field.Field` object, which defines
      and parses the header. It is populated from the class attributes.

      .. seealso::

         The |prepare|_ method sets up the initial field dictionary from
         those of the base classes; during class creation,
         :meth:`Field.__set_name__ <pcapkit.corekit.fields.field.FieldBase.__set_name__>`
         names each field object and adds it to the dictionary.

         .. |prepare| replace:: :meth:`__prepare__`
         .. _prepare: https://docs.python.org/3/reference/datamodel.html#preparing-the-class-namespace

    * :attr:`Schema.__additional__` and :attr:`Schema.__excluded__` list
      names to include in or exclude from the field dictionary, populated
      from the class attributes of the class and its bases.

      .. note::

         This metaclass's ``__new__`` inherits both lists from the base
         classes and extends them with the subclass's own.

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
    #: control, which would fail with an opaque ``TypeError`` frames away:
    #:
    #: * ``mcls``, ``name``, ``bases`` and ``namespace`` are
    #:   positional-or-keyword parameters of ``abc.ABCMeta.__new__`` before
    #:   Python 3.11, so a class keyword of the same name binds one twice;
    #:   hence ``ns=`` on the
    #:   :class:`~pcapkit.protocols.misc.pcapng.schema.Option` subclasses.
    #: * ``cls`` is bound first by every ``__init_subclass__``, in any class.
    #:
    #: Listed rather than derived from :func:`inspect.signature`, whose shape
    #: for ``ABCMeta.__new__`` varies across Python versions. ``attrs`` needs
    #: no entry, being positional-only below, as are ``name`` and ``bases``,
    #: which still collide one level up.
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
                parameter of ``abc.ABCMeta.__new__`` or of
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

        # NOTE: Never ``type.__new__``: skipping ``abc._abc_init`` would leave every Schema
        # subclass on the ``_abc_impl`` of ``Mapping``, corrupting ``isinstance`` against them.
        return super().__new__(cls, name, bases, attrs, **kwargs)  # type: ignore[return-value]


class Schema(ReduceAsProtocol2, Mapping[str, _VT], Generic[_VT], metaclass=SchemaMeta):
    """Schema for protocol headers.

    Note:
        Building a schema directly does not range-check its field values. A
        :class:`~pcapkit.corekit.fields.numbers.NumberField` masks an
        out-of-range integer to its width on packing, so e.g. ``70000`` in a
        two-octet field packs as ``0x1170``. The range checks live in each
        protocol's :meth:`~pcapkit.protocols.protocol.Protocol.make`, and in a
        field whose values have a range of their own, such as
        :class:`~pcapkit.corekit.fields.numbers.PortEnumField` (:issue:`2314`).

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
        #: Mapping of fields.
        __fields__: 'OrderedDict[str, FieldBase]'
        #: Mapping of field names to packed values.
        __buffer__: 'dict[str, bytes]'
        #: Whether the schema has changed since it was last packed, so that
        #: :meth:`__bytes__` packs it again.
        __updated__: 'bool'
        #: Octets of an enclosing :class:`~pcapkit.corekit.fields.misc.SchemaField`
        #: span that this nested schema left unread; set only when non-empty.
        __remainder__: 'bytes'
        #: Octets this nested schema read before :attr:`__remainder__`.
        __remainder_offset__: 'int'

    #: Flag for finalised class initialisation.
    __finalised__: 'FinalisedState' = FinalisedState.NONE

    #: Field name of the payload.
    __payload__: 'str' = 'payload'
    #: List of additional built-in names.
    __additional__: 'list[str]' = []
    #: List of names to be excluded from :obj:`dict` conversion.
    __excluded__: 'list[str]' = []

    @classmethod
    def from_dict(cls, dict_: 'Optional[Mapping[str, _VT] | Iterable[tuple[str, _VT]]]' = None,
                  **kwargs: '_VT') -> 'Self':
        r"""Create a new instance.

        * If ``dict_`` is a mapping, then does:
          ``for k in dict_: self[k] = dict_[k]``.
        * If ``dict_`` is present and not a mapping, then does:
          ``for k, v in dict_: self[k] = v``.
        * In either case, and if ``dict_`` is not present, this is followed
          by: ``for k, v in kwargs.items(): self[k] = v``.

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
            Only a nested :class:`Schema` that is an attribute's direct value
            is converted into :obj:`dict`; one held within another type, such
            as :obj:`list`, :obj:`tuple` or :obj:`set`, is left intact.

        Note:
            A schema unpacked as the value of a
            :class:`~pcapkit.corekit.fields.misc.SchemaField` that left part of
            the field's span unread carries those octets under a
            ``__remainder__`` key, and the number of octets it did read under
            ``__remainder_offset__``. :meth:`from_dict` accepts both back, so
            that the rebuilt field still packs them (:issue:`1380`). The keys
            are absent otherwise.

            A schema whose data ended inside one of its fields carries the
            ``__short_read__`` that :meth:`unpack` recorded, and
            :meth:`from_dict` accepts it back, likewise.

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

        for key in ('__remainder__', '__remainder_offset__', '__short_read__'):
            if key in self.__dict__:
                dict_[key] = self.__dict__[key]
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
            The packet's length being unknown, ``__length__`` defaults to
            ``-1``, which :class:`~pcapkit.corekit.fields.field.Field` takes
            as a placeholder; give ``__length__`` to pack the correct length.

        """
        if packet is None:
            packet = {}

        packet.update(self.__dict__)
        # NOTE: ``pre_unpack`` seeds keys both paths need, as HIP's ``EncryptedParameter``
        # does; ``pre_pack`` adds packing-only ones no field holds, e.g. the PCAP-NG SHB magic.
        self.pre_unpack(packet)
        self.pre_pack(packet)

        if '__length__' not in packet:
            packet['__length__'] = -1  # reasonable default value

        for field in self.__fields__.values():
            field = field(packet)

            # NOTE: From ``__dict__``, not ``getattr``, which returns the class's field
            # object for a field never set, so the absent-value branches would not fire.
            data = self.__dict__.get(self.__map__.get(field.name, field.name))

            if isinstance(field, PayloadField):
                # NOTE: ``ProtocolBase``, not ``Protocol``, which no built-in protocol
                # derives, so the payloads ``_make_payload`` returns pack.
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
                    # NOTE: A data model may hold a tuple, as HIP's ``group_id``; ``list()``
                    # keeps the signature of ``ListField.pack``, which only iterates it.
                    self.__buffer__[field.name] = field.pack(list(data), packet)
                else:
                    raise ProtocolUnbound(f'unsupported type {type(data)}')

                if isinstance(field, OptionField):
                    # NOTE: Mirrors the ``__option_padding__`` of ``unpack``, so padding fills
                    # the declared option area (#1289); an undeclared one leaves none.
                    packet['__option_padding__'] = max(field.length - len(self.__buffer__[field.name]), 0)
                continue

            if isinstance(field, PaddingField):
                # NOTE: the octets as captured, or zeros when there are none (#1223), per
                # :meth:`PaddingField.pack <pcapkit.corekit.fields.strings.PaddingField.pack>`.
                self.__buffer__[field.name] = field.pack(data, packet)
                continue

            if isinstance(field, ConditionalField):
                if not field.test(packet):
                    self.__buffer__[field.name] = b''
                    continue
                field = field.field(packet)

            if isinstance(field, ForwardMatchField):
                # NOTE: A forward match consumes nothing, here as in ``unpack``.
                self.__buffer__[field.name] = b''
                continue

            try:
                temp = field.pack(data, packet)
            except NoDefaultValue:
                temp = bytes(field.length)

            if isinstance(field, SchemaField) and len(temp) < field.length:
                # NOTE: Re-emit a nested schema's unread ``__remainder__`` at its ``__remainder_offset__``,
                # else zero-fill the width (#1292, #1380); not a SwitchField's, which spans the stream.
                if isinstance(data, Schema):
                    record = data.__dict__  # type: Mapping[str, Any]
                elif isinstance(data, collections.abc.Mapping):
                    record = data
                else:
                    record = {}
                tail = record.get('__remainder__', b'')
                if record.get('__remainder_offset__') != len(temp) or len(temp) + len(tail) > field.length:
                    tail = b''
                temp += tail + bytes(field.length - len(temp) - len(tail))
            self.__buffer__[field.name] = temp

        self.post_process(packet)
        self._cut_short_read()
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
            ``packet`` carries the bookkeeping keys below. For a nested schema,
            unpacked through a :class:`~pcapkit.corekit.fields.misc.SchemaField`,
            it is the context
            :func:`~pcapkit.corekit.fields.misc.nested_packet_context` builds: a
            name this schema does not declare falls through to the enclosing
            schema, which ``__packet__`` also holds.

            * ``__length__`` -- the length of the remaining data, which sizes
              the payload field.
            * ``__option_padding__`` -- how much of an
              :class:`~pcapkit.corekit.fields.collections.OptionField`'s
              declared area it left after its end-of-option-list marker.
              ``data`` is rewound by as much of that unparsed remainder as was
              read, so the fields sized from this key read the remainder itself
              and record a cut inside it (:issue:`2685`). What follows decides
              what it is: usually padding, but the PCAP-NG name resolution block
              reads further options from it.
            * ``__short_read__`` -- for the fields after the one the data ends
              inside, the ``(name, octets read)`` pair recorded, or that of a
              :class:`~pcapkit.corekit.fields.misc.ForwardMatchField` the data
              ends inside first, which the record leaves out as it consumes
              nothing. A field callback can so tell a value the end of the data
              left as zero from one read, and leave it to the short read.
            * ``__data_end__`` -- that ``length`` ends where the data does, as a
              :class:`~pcapkit.corekit.fields.collections.ListField` says of an
              item it counts. Fields running past ``length`` are then the cut
              the short read records, and do not warn that ``__length__`` fell
              below zero (:issue:`2749`).
            * ``__data_present__`` -- that ``data`` holds the data that many
              octets in, and past them the zeros a
              :class:`~pcapkit.corekit.fields.collections.ListField` of schema
              items filled it out with. The field a read crosses them in is given
              how many of its octets the data holds, under the same key, so a
              list there ends with the data (:issue:`2760`).

            The last three are cleared as unpacking starts, so a nested schema
            finds only its own.

            A payload field of a declared length the data ends inside records a
            cut like any other field, so its layer's rebuild reads as cut
            (:issue:`2711`); one declaring no length takes what the message
            leaves, as a trailer does, and records nothing. A
            :class:`~pcapkit.corekit.fields.collections.ListField` whose octets
            hold fewer items than it counts records the cut too, the missing
            items being its
            :attr:`~pcapkit.corekit.fields.collections.ListField.shortfall`.

        .. versionchanged:: 1.6.0

           The field the data ends inside is given to the fields after it, as
           ``__short_read__`` in ``packet`` (:issue:`2727`), a schema whose
           ``length`` ends with the data reads its fields past it as cut, not as
           a negative length (:issue:`2749`), and the field a read crosses the
           end of the data in, inside zeros filled out past it, is told where it
           ends (:issue:`2760`).

        """
        # force cast arg type since decorator changed their signatures
        if TYPE_CHECKING:
            data = cast('IO[bytes]', data)
            length = cast('int', length)
            packet = cast('dict[str, Any]', packet)

        # NOTE: ``packet`` may be an enclosing schema's, copied into a nested
        # context, so its short read is not this schema's (#2727).
        packet.pop('__short_read__', None)
        # NOTE: Fields running past a length that ends with the data are the cut its
        # short read records, not an overrun (#2749).
        data_end = packet.pop('__data_end__', False)
        # NOTE: Where ``data`` holds the data ends, past it the zero fill of a list of schema
        # items the data ends inside, which the field a read crosses it in is told of (#2760).
        present = cast('int', packet.pop('__data_present__', -1))
        fill = data.tell() + present if present >= 0 else -1

        self = cls.__new__(cls)
        for field in self.__fields__.values():
            field = field(packet)

            # NOTE: ``Field.length`` recomputes struct.calcsize() on every read,
            # so it is read once per field here rather than at each use.
            if isinstance(field, PayloadField):
                # NOTE: A negative length is the unset default and takes what is left, at
                # least nothing; a computed zero is an empty payload, not an unset one (#1275).
                length = declared = field.length
                if length < 0:
                    length = max(cast('int', packet['__length__']), 0)

                # NOTE: Bounded at ``sys.maxsize``, past which the read raises OverflowError
                # rather than coming back short, as every other overrun does (#1975).
                payload = data.read(min(length, sys.maxsize))
                self.__buffer__[field.name] = payload
                # NOTE: A payload of a declared length the data ends inside is recorded as
                # any field is; one taking what is left, as a trailer does, is not (#2711).
                if declared >= 0:
                    self._note_short_read(field.name, length, payload, packet)

                packet['__length__'] -= length
                packet[field.name] = payload

                setattr(self, field.name, payload)
                continue

            if isinstance(field, PaddingField):
                length = field.length

                byte = data.read(length)
                self.__buffer__[field.name] = byte
                self._note_short_read(field.name, length, byte, packet)

                packet[field.name] = byte
                packet['__length__'] -= length

                setattr(self, field.name, byte)
                continue

            if isinstance(field, ConditionalField):
                if not field.test(packet):
                    self.__buffer__[field.name] = b''
                    setattr(self, field.name, None)
                    packet[field.name] = NO_VALUE
                    continue
                field = field.field(packet)

            length = field.length

            # NOTE: bounded as the payload read above is (#1975).
            byte = data.read(min(length, sys.maxsize))
            self.__buffer__[field.name] = byte
            if not isinstance(field, (ForwardMatchField, OptionField)):
                self._note_short_read(field.name, length, byte, packet)

            context = packet.copy()
            if 0 <= fill < data.tell():
                context['__data_present__'] = max(fill - data.tell() + len(byte), 0)
            value = field.unpack(byte, context)
            if isinstance(field, ListField) and field.shortfall > 0:
                # NOTE: The data ended before the items the list counts, each at least an
                # octet, so it declares that many past those read (#2711).
                self._note_short_read(field.name, len(byte) + field.shortfall, byte, packet)
            if isinstance(field, SchemaField) and isinstance(value, Schema):
                # NOTE: On the nested schema, so the unread octets go wherever the value goes
                # (see ``pack``); summed from its buffers, as ``len`` may pack it again.
                consumed = sum(map(len, value.__buffer__.values()))
                if len(byte) > consumed:
                    value.__dict__['__remainder__'] = byte[consumed:]
                    value.__dict__['__remainder_offset__'] = consumed
            setattr(self, field.name, value)

            packet[field.name] = value

            if isinstance(field, OptionField):
                packet['__option_padding__'] = field.option_padding

            if isinstance(field, ForwardMatchField):
                # NOTE: A forward match consumes neither the stream nor ``__length__``, and its buffer
                # is zeroed as in ``pack``; the rewind is by the octets read, short near the end.
                data.seek(-len(byte), io.SEEK_CUR)
                self.__buffer__[field.name] = b''

                # NOTE: Left out of the record, but what it matched past the end of the
                # data is zeros all the same, so the fields after it are told (#2727).
                if len(byte) < length:
                    packet.setdefault('__short_read__', (field.name, len(byte)))
            elif isinstance(field, OptionField) and field.option_padding > 0:
                # NOTE: The option list ended before its declared area: give back what was read
                # of the rest, for the following fields to read and record a cut in (#2685).
                consumed = length - field.option_padding
                kept = min(consumed, len(byte))
                if kept < len(byte):
                    data.seek(kept - len(byte), io.SEEK_CUR)

                self.__buffer__[field.name] = byte[:kept]
                packet['__length__'] -= consumed
                if kept == len(byte):
                    self._note_short_read(field.name, length, byte, packet)
            else:
                if isinstance(field, OptionField):
                    self._note_short_read(field.name, length, byte, packet)
                packet['__length__'] -= length

            if packet['__length__'] < 0 and not data_end:
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

    def __init_subclass__(cls, /, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Refuse to derive from a finalised schema.

        :func:`~pcapkit.utilities.compat.final` only informs the type checker:
        it records ``__final__`` and leaves the class subclassable. A schema
        :func:`schema_final` finalises carries an ``__init__`` generated from
        its :attr:`__fields__` at that moment, which cannot set a field a
        subclass adds, so the subclass is refused.

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments in class definition.

        Raises:
            SchemaError: If any class in ``cls``'s ancestry carries the
                ``__final__`` marker in its own ``__dict__``.

        """
        # NOTE: The whole MRO, each read from its ``__dict__``, as ``Info.__init_subclass__`` does.
        for base in cls.__mro__[1:]:
            if base.__dict__.get('__final__'):
                raise SchemaError(f'{cls.__name__}: cannot subclass {base.__name__}, '
                                  'which is final')

        # NOTE: Forwarded, so an unaccepted class keyword fails in ``object``. ``EnumSchema``
        # consumes ``code`` and discards the rest, so tolerates a stray one.
        super().__init_subclass__(*args, **kwargs)

    def __new__(cls, *args: '_VT', **kwargs: '_VT') -> 'Self':  # pylint: disable=unused-argument
        """Create a new instance.

        The class will try to automatically generate ``__init__`` method with
        one keyword parameter per field in :attr:`__fields__`, which is
        inspired by :pep:`557` (:mod:`dataclasses`).

        Note:
            Whether ``cls`` still needs finalising is read from its *own*
            ``__dict__``, never inherited (:issue:`1498`). Each
            class is finalised on its first construction, whatever its
            ancestors' state, so a subclass of a
            :attr:`~pcapkit.corekit.infoclass.FinalisedState.BASE` ancestor
            still gets its own ``__builtin__``, ``__excluded__`` and generated
            ``__init__``, and a ``@final`` class under a ``BASE`` ancestor is
            refused like any other.

        Args:
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            SchemaError: If ``cls`` was marked with
                :func:`~pcapkit.utilities.compat.final` but never finalised by
                :func:`schema_final`, i.e. it carries ``__final__`` in its own
                ``__dict__`` without
                :attr:`~pcapkit.corekit.infoclass.FinalisedState.FINAL`.

        """
        # NOTE: Catches a bare ``@final`` once per class, as in ``Info.__new__``, via ``cls.__dict__``:
        # inherited, ``BASE`` leaks ``to_dict`` bookkeeping (#1498) and ``__final__`` blames a subclass.
        if cls.__dict__.get('__finalised__', FinalisedState.NONE) == FinalisedState.NONE:
            if cls.__dict__.get('__final__'):
                raise SchemaError(f'{cls.__name__}: marked final but never finalised, so it has no generated '
                                  '__init__; apply schema_final, which applies final itself, not final alone')
            cls = schema_final(cls, _finalised=False)
        self = super().__new__(cls)

        # NOTE: Set on ``self``, so they are not class variables shared by all instances.
        super().__setattr__(self, '__map__', {})
        super().__setattr__(self, '__map_reverse__', {})

        # NOTE: Per instance too, not shared through the class.
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
            # NOTE: A fallback, as ``from_dict`` seeds only given keys. Only ``NO_VALUE`` is unset:
            # ``None`` is a chosen absence, as ``unpack`` stores for a failed ConditionalField.
            value = self.__dict__.get(name, NO_VALUE)
            if value is not NO_VALUE:
                continue

            default = field.default
            if default is not NO_VALUE:
                self.__dict__[name] = default
            else:
                # NOTE: Dropped, not stored as ``None``, so ``pack``'s context leaves the name
                # for the schema to seed, as the PCAP-NG SHB's ``pre_pack`` seeds its magic.
                self.__dict__.pop(name, None)

        # NOTE: Only with a context: a field callback may read the enclosing layer's keys,
        # as the MPTCP options do; otherwise ``__bytes__`` packs it on first use.
        if packet is not None:
            self.pack(packet)

    def __update__(self, dict_: 'Optional[Mapping[str, _VT] | Iterable[tuple[str, _VT]]]' = None,
                   **kwargs: '_VT') -> 'None':
        # NOTE: A key named like a builtin method is stored as ``_<ClassName><key>``,
        # the renaming kept both ways in ``__map__`` and ``__map_reverse__``.

        __name__ = type(self).__name__  # pylint: disable=redefined-builtin

        if dict_ is None:
            data_iter = kwargs.items()  # type: Iterable[tuple[str, Any]]
        elif isinstance(dict_, collections.abc.Mapping):
            data_iter = itertools.chain(dict_.items(), kwargs.items())
        else:
            data_iter = itertools.chain(dict_, kwargs.items())

        for (key, value) in data_iter:
            # NOTE: Not fields: the unread octets of an enclosing ``SchemaField`` span,
            # which a rebuild re-emits (#1380), and the short read ``unpack`` records (#1458).
            if key in ('__remainder__', '__remainder_offset__', '__short_read__'):
                self.__dict__[key] = value
                continue

            if key not in self.__buffer__:
                warn(f'{key!r} is not a valid field name', UnknownFieldWarning)
                continue

            if key in self.__builtin__:
                new_key = f'_{__name__}{key}'

                self.__map__[key] = new_key
                self.__map_reverse__[new_key] = key

                key = new_key

            # if key in self.__dict__:
            #     raise KeyExists(f'{key!r} already exists')

            # NOTE: Keys are kept as given, even where ``getattr`` cannot reach them.

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
        # NOTE: Every key ``__iter__`` yields, so ``dict(schema)`` reads the values a
        # ``post_process`` stores, as IPv4's ``TSOption`` does (#1291); mangled keys by origin.
        if name in self.__fields__ or (name not in self.__builtin__ and name not in self.__map_reverse__):
            key = self.__map__.get(name, name)
            return self.__dict__[key]
        raise KeyError(name)

    def __setattr__(self, name: 'str', value: '_VT') -> 'None':
        if name in self.__fields__:
            key = self.__map__.get(name, name)
            self.__dict__[key] = value
            # NOTE: Stored directly, rather than re-entering this method, as ``__new__`` set it.
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

    def _note_short_read(self, name: 'str', length: 'int', byte: 'bytes',
                         packet: 'Optional[dict[str, Any]]' = None) -> 'None':
        """Record the first field the data ends inside, for :meth:`_cut_short_read`.

        Args:
            name: Field name.
            length: Octets the field declares.
            byte: Octets actually read for it.
            packet: Unpacked data, where the fields after it find the record,
                unless a forward match the data ended inside is there first
                (see :meth:`unpack`). Without it, the record is kept on the
                schema alone.

        """
        if len(byte) < length and '__short_read__' not in self.__dict__:
            self.__dict__['__short_read__'] = (name, len(byte))
            if packet is not None:
                packet.setdefault('__short_read__', self.__dict__['__short_read__'])

    def _cut_short_read(self) -> 'None':
        """Cut the packed buffers back to the octets a short read consumed.

        A schema whose data ended inside one of its fields records, as
        ``__short_read__``, that field's name and how many of its octets were
        there (see :meth:`unpack`). Its value is read as though the missing
        octets were zeros, so packing it writes the field at full width and
        every field after it besides, none of which was captured. Only the
        octets read are kept here, so a truncated header packs back to exactly
        what was captured (:issue:`1458`).

        """
        record = self.__dict__.get('__short_read__')
        if record is None:
            return

        name, count = record
        cut = False
        for key in self.__fields__:
            if cut:
                self.__buffer__[key] = b''
            elif key == name:
                self.__buffer__[key] = self.__buffer__[key][:count]
                cut = True

    def _frame_end_field(self) -> 'Optional[str]':
        """The field this header's message runs to the end of its frame in, if any.

        Returns:
            The last field sized by what is left of the length the layer was
            given, as :class:`~pcapkit.protocols.link.gre.schema.GRE`'s payload
            is: the message runs on in it to the end of whatever holds it.
            :data:`None` where the last field is instead fixed or sized by the
            header, as UDP's payload is by its Length and an HTTP/2 frame's by
            its own, since the message then ends where its header says
            (:issue:`2711`), and where it is a list, as SCTP's chunks are, whose
            buffer holds only what its items took. A payload field declaring no
            length at all, as a trailer or the next record does, takes what the
            message leaves, and is passed over.

        Each field's length is resolved from this schema's own values under two
        lengths given; the one that changes with them is sized by what was left.
        :func:`~pcapkit.corekit.schema.shortread.keep_short_read` records a
        frame the capture cut short on that field.

        """
        packet = dict(self.__dict__)
        for name, field in reversed(self.__fields__.items()):
            try:
                if isinstance(field, ConditionalField) and not field.test(packet):
                    continue
                # NOTE: Lengths far past any message, so a ``max(..., 0)`` callback still moves.
                resolved = field(dict(packet, __length__=0x7FFF_FFFE))
                near, far = resolved.length, field(dict(packet, __length__=0x7FFF_FFFF)).length
            except Exception:  # a length its own values cannot resolve
                return None
            if isinstance(field, PayloadField) and far < 0:
                continue
            # NOTE: A list keeps in its buffer only the octets its items took, not the
            # rest of the layer's, so a cut recorded on it would drop them (#2711).
            if any(isinstance(kind, (ListField, ForwardMatchField))
                   for kind in (resolved, getattr(resolved, 'field', None))):
                return None
            return name if near != far else None
        return None


class _EnumRegistry(collections.defaultdict):
    """A registry :class:`collections.defaultdict` that never inserts a miss.

    :attr:`EnumSchema.registry` (and its class-level twin,
    :attr:`EnumMeta.registry
    <pcapkit.protocols.schema.EnumMeta.registry>`) is read with a bare
    ``registry[code]`` across the schema layer, e.g.
    ``Option.registry[type]``. A plain :class:`collections.defaultdict` would
    insert what :attr:`~collections.defaultdict.default_factory` returns on
    the first miss, and the registry lives on the *class*, so one packet with
    an unrecognised code would grow it for the rest of the process, and make a
    later, legitimate :meth:`EnumSchema.register` report an overwrite that
    never happened.

    The fallback is how an unknown option, chunk or block gets its
    ``Unknown*``/``Unassigned*`` schema, so this subclass still returns it,
    without recording it, as :meth:`Protocol._lookup_registry
    <pcapkit.protocols.protocol.Protocol._lookup_registry>` does for the
    ``__proto__`` family.

    """

    def __missing__(self, key: 'Any') -> 'Any':
        """Return the fallback for an unregistered ``key``, without storing it.

        Args:
            key: Registry key that is not registered.

        Returns:
            What :attr:`~collections.defaultdict.default_factory` returns. The
            registry is left as it was, so ``key`` stays unregistered.

        Raises:
            KeyError: If :attr:`~collections.defaultdict.default_factory` is
                :data:`None`.

        """
        if self.default_factory is None:
            raise KeyError(key)
        return self.default_factory()


class EnumMeta(SchemaMeta, Generic[_ET]):
    """Meta class to add dynamic support for :class:`EnumSchema`.

    It adds :attr:`~EnumSchema.registry` to subclasses: a read-only class
    property returning the :attr:`EnumSchema.__enum__` mapping.

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

        Subclass it with the enumeration:

        .. code-block:: python

           class MySchema(EnumSchema[MyEnum]):

               # optional, set the default schema for enumeration mapping
               # if the enumeration number is not found in the mapping
               __default__ = lambda: UnknownSchema  # by default, None

        then subclass that per code, or list of codes:

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
            This property answers on an instance; on the class, the same
            mapping is served by :attr:`EnumMeta.registry <pcapkit.protocols.schema.EnumMeta.registry>`.

        Important:
            See :attr:`EnumMeta.registry
            <pcapkit.protocols.schema.EnumMeta.registry>`: the
            returned mapping is a
            :class:`_EnumRegistry`, so looking up an unregistered ``code``
            returns the default schema without recording ``code`` as if it
            had been registered.

        """
        return self.__enum__

    @classmethod
    def register(cls, code: '_ET', schema: 'Type[Self]') -> 'None':
        """Register enumeration to :attr:`__enum__` mapping.

        Args:
            code: Enumeration code.
            schema: Enumeration schema.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If ``code`` is already
                registered, naming the displaced schema and its replacement.

        Note:
            Each registrar in :mod:`pcapkit.foundation.registry.protocols` that
            takes a ``schema`` registers both halves of one binding, a parser
            through e.g. :meth:`IPv4.register_option
            <pcapkit.protocols.internet.ipv4.protocol.IPv4.register_option>` and
            a schema through this method, and both warn on an overwrite.

            Registering the same schema object again is a silent no-op.
            Presence is a faithful test only because :class:`_EnumRegistry`
            does not record a miss.

            :class:`pcapkit.protocols.misc.pcapng.schema.Option` overrides this
            method with a namespaced registry of its own, guarded separately.

        """
        incumbent = cls.__enum__.get(code)  # type: ignore[arg-type]
        if incumbent is not None and incumbent is not schema:
            warn(f'schema {code} already registered, overwriting '
                 f'{incumbent!r} with {schema!r}', RegistryWarning)

        cls.__enum__[code] = schema  # type: ignore[index]

    def __init_subclass__(cls, /, code: 'Optional[_ET | Iterable[_ET]]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Register enumeration to :attr:`registry` mapping.

        Args:
            code: Enumeration code. It can be either a single enumeration
                or a list of enumerations.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        A subclass given ``code`` is registered under it in :attr:`registry`;
        one without is not.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If any of ``code`` is
                already registered, naming the displaced schema and its
                replacement, as :meth:`register` does: a class declaration such
                as ``class MyOption(Option, code=...)`` writes the registry
                without calling it.

        Notes:
            An undefined :attr:`__enum__` becomes an :class:`_EnumRegistry`
            defaulting to :attr:`__default__`.

            To customise the mapping, override this method and define
            :attr:`__enum__` manually. A plain :class:`collections.defaultdict`
            defined so, as for the namespaced mapping of
            :class:`pcapkit.protocols.misc.pcapng.schema.Option`, is swapped
            for an :class:`_EnumRegistry` before anything else can hold it.

        """
        # NOTE: First, so a refused subclass of a finalised schema never reaches the
        # registry; ``code`` is consumed here and the rest are dropped.
        super().__init_subclass__()

        if not hasattr(cls, '__enum__'):
            cls.__enum__ = _EnumRegistry(cls.__default__)
        elif '__enum__' in cls.__dict__ and not isinstance(cls.__dict__['__enum__'], _EnumRegistry):
            # A plain ``defaultdict`` from the class body, swapped while nothing else
            # can hold it, so every later read sees the same safe object.
            manual = cls.__dict__['__enum__']
            cls.__enum__ = _EnumRegistry(getattr(manual, 'default_factory', None), manual)

        if code is not None:
            # Not ``cls.register``, which the PCAP-NG ``Option`` overrides incompatibly.
            codes = code if isinstance(code, collections.abc.Iterable) else (code,)
            for _code in codes:
                # A repeated member, as ``code=[A, A]`` or an enum alias makes, meets
                # ``cls`` as its own incumbent, which is no overwrite.
                incumbent = cls.__enum__.get(_code)  # type: ignore[arg-type]
                if incumbent is not None and incumbent is not cls:
                    warn(f'schema {_code} already registered, overwriting '
                         f'{incumbent!r} with {cls!r}', RegistryWarning)
                cls.__enum__[_code] = (cls)  # type: ignore[index]
