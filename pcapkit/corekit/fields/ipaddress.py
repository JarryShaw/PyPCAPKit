# -*- coding: utf-8 -*-
"""IP address field class"""

import abc
import contextlib
import ipaddress
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from pcapkit.corekit.fields.field import Field, NoValue
from pcapkit.utilities.exceptions import FieldValueError

__all__ = [
    'IPv4AddressField', 'IPv6AddressField',
    'IPv4InterfaceField', 'IPv6InterfaceField',
    'parse_ip_address',
]

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
    from typing import Any, Callable, Iterator, Optional

    from typing_extensions import Literal, Self

    from pcapkit.corekit.fields.field import NoValueType


_T = TypeVar('_T', 'IPv4Address', 'IPv6Address',
             'IPv4Interface', 'IPv6Interface')
_AT = TypeVar('_AT', 'IPv4Address', 'IPv6Address')
_IT = TypeVar('_IT', 'IPv4Interface', 'IPv6Interface')


@contextlib.contextmanager
def _reraise_as_field_value_error(description: str) -> 'Iterator[None]':
    """Translate a bare :exc:`ValueError` from :mod:`ipaddress` into :exc:`FieldValueError`.

    Every conversion in this module ultimately calls into the stdlib
    :mod:`ipaddress` module, which raises a bare :exc:`ValueError` (or a
    subclass of it, e.g. :exc:`~ipaddress.AddressValueError` or
    :exc:`~ipaddress.NetmaskValueError`) for a malformed value. Left alone,
    that exception is not an instance of
    :exc:`~pcapkit.utilities.exceptions.BaseError`, unlike every other
    exception this module raises -- so a caller cannot rely on
    ``except BaseError`` to catch a bad field value. Wrapping the conversion
    in this context manager re-raises it as :exc:`FieldValueError` instead,
    preserving the original message.

    Args:
        description: Human-readable description of the value being
            converted, used to build the :exc:`FieldValueError` message.

    Raises:
        FieldValueError: If the code inside the ``with`` block raises
            :exc:`ValueError`.

    """
    try:
        yield
    except FieldValueError:
        # NOTE: ``FieldValueError`` is itself a ``ValueError``, so without this
        # clause first, a ``FieldValueError`` raised inside the ``with`` block
        # (e.g. a version-mismatch check) would be caught below and re-wrapped,
        # losing its original message. Callers are expected to keep such
        # raises outside the ``with`` block, but this is the same ordering
        # trap ``ProtocolError`` carries at ``exceptions.py``, so it is guarded
        # here too rather than relied upon by convention alone.
        raise
    except ValueError as error:
        raise FieldValueError(f'{description}: {error}') from error


def _reject_bool(value: 'object', description: str) -> 'None':
    """Reject a :obj:`bool` value before it reaches :mod:`ipaddress`.

    Args:
        value: Value to check.
        description: Human-readable description of what ``value`` is, used
            to build the :exc:`FieldValueError` message.

    Raises:
        FieldValueError: If ``value`` is a :obj:`bool`.

    Notes:
        :obj:`bool` is an :class:`int` subclass, and every conversion in this
        module ultimately calls :func:`ipaddress.ip_address` or
        :func:`ipaddress.ip_interface`, both of which treat any :class:`int`
        below ``2**32`` as IPv4 -- so without this guard, ``True``/``False``
        are silently accepted as ``0.0.0.1``/``0.0.0.0`` (or the equivalent
        interface) on an IPv4-typed field, with **no exception and no
        warning**. On an IPv6-typed field the same conversion happens to
        raise instead, because the resulting
        :class:`~ipaddress.IPv4Address`'s version mismatches -- and that
        asymmetry is exactly what let this slip past #481's otherwise
        equivalent guard for :meth:`MH._make_opt_mn_id
        <pcapkit.protocols.internet.mh.MH._make_opt_mn_id>` (c.f. #491).

        Every caller checks this *before* dispatching on the value's type,
        for the same placement reason #481 gives: a correct check in the
        wrong position does not fire, and that placement mistake has
        already been made twice in this repository's history.

        Guarding the field classes is necessary but not sufficient, because a
        ``_make_*`` that must know the address family before it can build the
        schema converts the argument itself and so never hands this module a
        :obj:`bool` at all. :func:`parse_ip_address` is where those callers
        reach this guard (c.f. #508).

    """
    if isinstance(value, bool):
        raise FieldValueError(
            f'{description}: must not be a bool, not {value!r} -- pass '
            f'int({value!r}) if the numeric value is what is wanted')


def parse_ip_address(value: 'IPv4Address | IPv6Address | bytes | int | str',
                     description: str,
                     version: 'Optional[int]' = None) -> 'IPv4Address | IPv6Address':
    """Convert a caller-supplied address on the **construction** path.

    Args:
        value: Address as the caller gave it -- an :mod:`ipaddress` object,
            which is returned unchanged, or anything :mod:`ipaddress` accepts.
        description: Human-readable description of what ``value`` is, used to
            build the :exc:`FieldValueError` message. Callers in a protocol
            should carry their usual context into it, e.g.
            ``f'{self.alias}: [OptNo {type}] care-of address'``.
        version: IP version to demand, ``4`` or ``6``, or :obj:`None` to take
            whichever family ``value`` describes. Pass it where the wire format
            fixes the family, so that an :class:`int` is widened to the right
            one -- ``258`` is ``::102`` for ``version=6`` but ``0.0.1.2`` for
            :func:`ipaddress.ip_address`.

    Returns:
        The converted address.

    Raises:
        FieldValueError: If ``value`` is a :obj:`bool` (c.f.
            :func:`_reject_bool`), is not a valid IP address, or is not of
            ``version``.

    Notes:
        This is the sanctioned way for a ``_make_*`` method to turn a
        caller-supplied address into an :mod:`ipaddress` object, and it exists
        because doing it with :func:`ipaddress.ip_address` directly is what
        #508 turned out to be: a ``_make_*`` that has to know the address
        *family* before it can build the schema -- to size an option whose
        length is the only thing on the wire that carries the family -- must
        convert the argument itself, and that conversion happens **before** the
        schema, so it launders a :obj:`bool` into an
        :class:`~ipaddress.IPv4Address` that #500's guard in
        :meth:`_IPAddressField.pre_process` can then only see as a legitimate
        address. Seven such call sites took ``True`` / ``False`` without
        complaint as ``0.0.0.1`` / ``0.0.0.0`` -- or ``::1`` / ``::`` where the
        wire format fixes the family as IPv6 -- and six of them went on to pack
        those octets. The seventh,
        :meth:`TCP._make_mptcp_addaddr
        <pcapkit.protocols.transport.tcp.TCP._make_mptcp_addaddr>`, built an
        equally corrupt schema and is only stopped from packing it by an
        unrelated defect of its own.

        Routing every one of them through here rather than giving each its own
        :func:`isinstance` check is the whole point: #481 added exactly such a
        check to :meth:`MH._make_opt_mn_id
        <pcapkit.protocols.internet.mh.MH._make_opt_mn_id>`, and #491 was the
        same defect surviving at every site that had not been thought of. A
        guard that has to be remembered per call site is a guard that will be
        forgotten at the next one.

        The :obj:`bool` rejection is the **first** statement here, ahead of any
        dispatch on the value's type, for the placement reason #481 gives and
        :func:`_reject_bool` repeats.

        This raises :exc:`FieldValueError` and not
        :exc:`~pcapkit.utilities.exceptions.ProtocolError`, which is deliberate
        even though two sibling guards for the same mistake --
        :meth:`MH._make_opt_mn_id
        <pcapkit.protocols.internet.mh.MH._make_opt_mn_id>` from #481 and
        :class:`ESP's SecurityAssociation
        <pcapkit.protocols.internet.esp.SecurityAssociation>` from #491 -- raise
        the latter. The layer decides: this is a field-level conversion, so it
        answers with what :meth:`_IPAddressField.pre_process` answers with for
        the identical value, and a caller sees one exception whether the
        :obj:`bool` reached the field through the schema or through a
        ``_make_*``. The two protocol-level guards answer for the *option*,
        alongside siblings that are not about addresses at all --
        ``_make_opt_mn_id`` refuses a :obj:`bool` for all eight MN-ID subtypes,
        only one of which is address-typed -- so neither can route through here
        without losing the subtype-aware message that is the point of it. Both
        exception classes derive from
        :exc:`~pcapkit.utilities.exceptions.BaseError` *and* :exc:`ValueError`,
        so the difference is invisible to ``except BaseError`` and ``except
        ValueError``, and nothing in the library catches either one
        specifically.

    """
    _reject_bool(value, description)

    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = value  # type: IPv4Address | IPv6Address
    else:
        with _reraise_as_field_value_error(description):
            if version == 4:
                ip = ipaddress.IPv4Address(value)
            elif version == 6:
                ip = ipaddress.IPv6Address(value)
            else:
                ip = ipaddress.ip_address(value)

    # NOTE: Checked outside the ``with`` block above, and after it, because an
    # :mod:`ipaddress` object taken from the branch that skips the conversion
    # has not been version-checked at all -- ``IPv6Address(IPv4Address(...))``
    # would have raised, but returning the object unchanged cannot.
    if version is not None and ip.version != version:
        raise FieldValueError(f'{description}: IP version mismatch: {ip.version} != {version}')
    return ip


class _IPField(Field[_T], Generic[_T]):
    """Internal IP related value for protocol fields.

    Args:
        length: Field size (in bytes).
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    @abc.abstractmethod
    def version(self) -> 'int':
        """IP version number."""


class _IPAddressField(_IPField[_AT]):
    """Internal IP address value for protocol fields.

    Args:
        length: Field size (in bytes).
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    def pre_process(self, value: '_AT | bytes | int | str', packet: 'dict[str, Any]') -> 'bytes':
        """Process field value before packing.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If ``value`` is a :obj:`bool` (c.f.
                :func:`_reject_bool`), is not a valid IP address, or is the
                wrong IP version for this field.

        """
        _reject_bool(value, 'invalid IP address')

        if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip = value  # type: IPv4Address | IPv6Address
        else:
            with _reraise_as_field_value_error('invalid IP address'):
                ip = ipaddress.ip_address(value)

        if ip.version != self.version:
            raise FieldValueError(f'IP version mismatch: {ip.version} != {self.version}')
        return ip.packed

    def post_process(self, value: 'bytes', packet: 'dict[str, Any]') -> '_AT':
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If ``value`` is the wrong IP version for this
                field. ``value`` cannot actually fail the underlying
                :func:`ipaddress.ip_address` conversion here -- it is always
                exactly 4 or 16 octets, fixed by this field's length, and any
                such octet string is a valid address -- but the conversion is
                still wrapped for consistency with the rest of this module.

        """
        with _reraise_as_field_value_error('invalid IP address'):
            val = ipaddress.ip_address(value)
        if val.version != self.version:
            raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')
        return val  # type: ignore[return-value]


class IPv4AddressField(_IPAddressField[ipaddress.IPv4Address]):
    """IPv4 address value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def version(self) -> 'Literal[4]':
        """IP version number."""
        return 4

    def __init__(self, default: 'IPv4Address | NoValueType' = NoValue,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(4, default, callback)

        self._template = f'4s'


class IPv6AddressField(_IPAddressField[ipaddress.IPv6Address]):
    """IPv6 address value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def version(self) -> 'Literal[6]':
        """IP version number."""
        return 6

    def __init__(self, default: 'IPv6Address | NoValueType' = NoValue,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(16, default, callback)

        self._template = f'16s'


class _IPInterfaceField(_IPField[_IT]):
    """Internal IP interface value for protocol fields.

    Args:
        length: Field size (in bytes); if a callable is given, it should return
            an integer value and accept the current packet as its only argument.
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """


class IPv4InterfaceField(_IPInterfaceField[ipaddress.IPv4Interface]):
    """IPv4 interface value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def version(self) -> 'Literal[4]':
        """IP version number."""
        return 4

    def __init__(self, default: 'IPv4Interface | NoValueType' = NoValue,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(8, default, callback)

        self._template = f'8s'

    def pre_process(self, value: 'IPv4Interface | bytes | int | str', packet: 'dict[str, Any]') -> 'bytes':
        """Process field value before packing.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If ``value`` is a :obj:`bool` (c.f.
                :func:`_reject_bool`), is not a valid IP interface, or is the
                wrong IP version for this field.

        """
        _reject_bool(value, 'invalid IP interface')

        if isinstance(value, ipaddress.IPv4Interface):
            val = value
        else:
            with _reraise_as_field_value_error('invalid IP interface'):
                parsed = ipaddress.ip_interface(value)
            if not isinstance(parsed, ipaddress.IPv4Interface):
                raise FieldValueError(f'IP version mismatch: {parsed.version} != {self.version}')
            val = parsed

        ip = val.ip
        mask = val.netmask
        return ip.packed + mask.packed

    def post_process(self, value: 'bytes', packet: 'dict[str, Any]') -> 'IPv4Interface':
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If the trailing four octets are not a valid
                dotted netmask, or if the resulting interface is the wrong IP
                version for this field. The leading four octets cannot
                actually fail here -- they are always exactly 4 octets, fixed
                by this field's length, and any such octet string is a valid
                address -- but the conversion is still wrapped for
                consistency with the rest of this module.

        Notes:
            The trailing four octets are a dotted netmask, as written by
            :meth:`pre_process` -- not a prefix length as in
            :meth:`IPv6InterfaceField.post_process`.

        """
        with _reraise_as_field_value_error('invalid IPv4 address'):
            ip = ipaddress.IPv4Address(value[:4])
            mask = ipaddress.IPv4Address(value[4:])

        with _reraise_as_field_value_error('invalid IPv4 interface'):
            val = ipaddress.ip_interface(f'{ip}/{mask}')
        if not isinstance(val, ipaddress.IPv4Interface):
            raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')
        return val


class IPv6InterfaceField(_IPInterfaceField[ipaddress.IPv6Interface]):
    """IPv6 interface value for protocol fields.

    Args:
        default: Field default value, if any.
        callback: Callback function to be called upon
            :meth:`self.__call__ <pcapkit.corekit.fields.field.FieldBase.__call__>`.

    """

    @property
    def version(self) -> 'Literal[6]':
        """IP version number."""
        return 6

    def __init__(self, default: 'IPv6Interface | NoValueType' = NoValue,
                 callback: 'Callable[[Self, dict[str, Any]], None]' = lambda *_: None) -> 'None':
        super().__init__(17, default, callback)

        self._template = f'17s'

    def pre_process(self, value: 'IPv6Interface | bytes | int | str', packet: 'dict[str, Any]') -> 'bytes':
        """Process field value before packing.

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If ``value`` is a :obj:`bool` (c.f.
                :func:`_reject_bool`), is not a valid IP interface, or is the
                wrong IP version for this field.

        """
        _reject_bool(value, 'invalid IP interface')

        if isinstance(value, ipaddress.IPv6Interface):
            val = value
        else:
            with _reraise_as_field_value_error('invalid IP interface'):
                parsed = ipaddress.ip_interface(value)
            if not isinstance(parsed, ipaddress.IPv6Interface):
                raise FieldValueError(f'IP version mismatch: {parsed.version} != {self.version}')
            val = parsed

        ip = val.ip
        prefixlen = cast('int', val._prefixlen)  # type: ignore[attr-defined] # pylint: disable=protected-access
        return ip.packed + prefixlen.to_bytes(1, 'big')

    def post_process(self, value: 'bytes', packet: 'dict[str, Any]') -> 'IPv6Interface':
        """Process field value after parsing (unpacking).

        Args:
            value: Field value.
            packet: Packet data.

        Returns:
            Processed field value.

        Raises:
            FieldValueError: If the trailing octet is not a valid IPv6 prefix
                length, i.e. greater than 128, or if the resulting interface
                is the wrong IP version for this field. Neither the leading
                sixteen octets nor the final :func:`ipaddress.ip_interface`
                call can actually fail here -- the former is always exactly
                16 octets, fixed by this field's length, and any such octet
                string is a valid address; the latter is only ever reached
                once the prefix length has already been checked above, and
                any prefix length in ``0..128`` is valid. Both conversions
                are still wrapped for consistency with the rest of this
                module.

        Notes:
            The trailing octet is the prefix length as a binary integer, as
            written by :meth:`pre_process` -- not a dotted netmask as in
            :meth:`IPv4InterfaceField.post_process`.

        """
        with _reraise_as_field_value_error('invalid IPv6 address'):
            ip = ipaddress.IPv6Address(value[:16])
        prefixlen = value[16]

        if prefixlen > 128:
            raise FieldValueError(f'invalid IPv6 prefix length: {prefixlen}')

        with _reraise_as_field_value_error('invalid IPv6 interface'):
            val = ipaddress.ip_interface(f'{ip}/{prefixlen}')
        if not isinstance(val, ipaddress.IPv6Interface):
            raise FieldValueError(f'IP version mismatch: {val.version} != {self.version}')
        return val
