# -*- coding: utf-8 -*-
"""IP Address Conversion
===========================

.. module:: pcapkit.corekit.schema.ipaddress

:mod:`pcapkit.corekit.schema.ipaddress` converts a caller-supplied IP address to an
:mod:`ipaddress` object, refusing a :obj:`bool` before :mod:`ipaddress` reads it as
an :class:`int` (:issue:`491`), for the IP address fields
(:mod:`pcapkit.corekit.fields.ipaddress`) and the protocols' makers alike. It is one
of the :mod:`pcapkit.corekit.schema` helpers shared across the schema layer, not
part of the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.corekit.fields.ipaddress``, with the guards the
   IP address fields share (:issue:`2674`).

"""

import contextlib
import ipaddress
from typing import TYPE_CHECKING

from pcapkit.utilities.exceptions import FieldValueError

__all__ = ['parse_ip_address']

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Iterator, Optional


@contextlib.contextmanager
def _reraise_as_field_value_error(description: str) -> 'Iterator[None]':
    """Translate a bare :exc:`ValueError` from :mod:`ipaddress` into :exc:`FieldValueError`.

    Every conversion here and in :mod:`pcapkit.corekit.fields.ipaddress`
    ultimately calls into the stdlib
    :mod:`ipaddress` module, which raises a bare :exc:`ValueError` (or a
    subclass of it, e.g. :exc:`~ipaddress.AddressValueError` or
    :exc:`~ipaddress.NetmaskValueError`) for a malformed value. Left alone,
    that exception is not an instance of
    :exc:`~pcapkit.utilities.exceptions.BaseError`, unlike every other
    exception those modules raise -- so a caller cannot rely on
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
            to build the :exc:`~pcapkit.utilities.exceptions.FieldValueError` message.

    Raises:
        FieldValueError: If ``value`` is a :obj:`bool`.

    Notes:
        :obj:`bool` is an :class:`int` subclass, and every conversion here and
        in :mod:`pcapkit.corekit.fields.ipaddress` ultimately calls
        :func:`ipaddress.ip_address` or
        :func:`ipaddress.ip_interface`, both of which treat any :class:`int`
        below ``2**32`` as IPv4 -- so without this guard, ``True``/``False``
        are silently accepted as ``0.0.0.1``/``0.0.0.0`` (or the equivalent
        interface) on an IPv4-typed field, with **no exception and no
        warning**. On an IPv6-typed field the same conversion happens to
        raise instead, because the resulting
        :class:`~ipaddress.IPv4Address`'s version mismatches -- and that
        asymmetry is exactly what let this slip past :issue:`469`'s otherwise
        equivalent guard for :meth:`MH._make_opt_mn_id
        <pcapkit.protocols.internet.mh.MH._make_opt_mn_id>` (cf.
        :issue:`491`).

        Every caller checks this *before* dispatching on the value's type,
        for the same placement reason :issue:`469` gives: a correct check
        in the wrong position does not fire.

        Guarding the field classes is necessary but not sufficient, because a
        ``_make_*`` that must know the address family before it can build the
        schema converts the argument itself and so never hands the fields a
        :obj:`bool` at all. :func:`parse_ip_address` is where those callers
        reach this guard (cf. :issue:`508`).

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
            build the :exc:`~pcapkit.utilities.exceptions.FieldValueError`
            message. Callers in a protocol should carry their usual context
            into it, e.g. ``f'{self.alias}: [OptNo {type}] care-of address'``.
        version: IP version to demand, ``4`` or ``6``, or :obj:`None` to take
            whichever family ``value`` describes. Pass it where the wire format
            fixes the family, so that an :class:`int` is widened to the right
            one -- ``258`` is ``::102`` for ``version=6`` but ``0.0.1.2`` for
            :func:`ipaddress.ip_address`.

    Returns:
        The converted address.

    Raises:
        FieldValueError: If ``value`` is a :obj:`bool` (cf.
            :func:`_reject_bool`), is not a valid IP address, or is not of
            ``version``.

    Notes:
        This is the sanctioned way for a ``_make_*`` method to turn a
        caller-supplied address into an :mod:`ipaddress` object, and it exists
        because doing it with :func:`ipaddress.ip_address` directly is the
        defect :issue:`508` found: a ``_make_*`` that has to know the address
        *family* before it can build the schema -- to size an option whose
        length is the only thing on the wire that carries the family -- must
        convert the argument itself, and that conversion happens **before**
        the schema, so it launders a :obj:`bool` into an
        :class:`~ipaddress.IPv4Address` that the :issue:`491` guard in
        :meth:`_IPAddressField.pre_process
        <pcapkit.corekit.fields.ipaddress._IPAddressField.pre_process>` can then only see as a
        legitimate address: ``True`` / ``False`` become ``0.0.0.1`` /
        ``0.0.0.0`` -- or ``::1`` / ``::`` where the wire format fixes the
        family as IPv6 -- without complaint.

        Routing every one of them through here rather than giving each its own
        :func:`isinstance` check is the whole point: :meth:`MH._make_opt_mn_id
        <pcapkit.protocols.internet.mh.MH._make_opt_mn_id>` carries exactly
        such a check (:issue:`469`), and :issue:`491` is the same defect at
        every site that lacks one. A guard that has to be remembered per call
        site is a guard that will be forgotten at the next one.

        The :obj:`bool` rejection is the **first** statement here, ahead of any
        dispatch on the value's type, for the placement reason :issue:`469`
        gives and :func:`_reject_bool` repeats.

        This raises :exc:`~pcapkit.utilities.exceptions.FieldValueError` and not
        :exc:`~pcapkit.utilities.exceptions.ProtocolError`, which is deliberate
        even though sibling guards for the same mistake --
        :meth:`MH._make_opt_mn_id
        <pcapkit.protocols.internet.mh.MH._make_opt_mn_id>` from :issue:`469`
        and :class:`ESP's SecurityAssociation
        <pcapkit.protocols.internet.esp.SecurityAssociation>` from :issue:`491`
        -- raise the latter. The layer decides: this is a field-level
        conversion, so it answers with what :meth:`_IPAddressField.pre_process
        <pcapkit.corekit.fields.ipaddress._IPAddressField.pre_process>`
        answers with for the identical value, and a caller sees one exception
        whether the :obj:`bool` reached the field through the schema or through
        a ``_make_*``. Those protocol-level guards answer for the *option*,
        alongside siblings that are not about addresses at all --
        ``_make_opt_mn_id`` refuses a :obj:`bool` for every MN-ID subtype,
        address-typed or not -- so none of them can route through here
        without losing the subtype-aware message that is the point of it. Both
        exception classes derive from
        :exc:`~pcapkit.utilities.exceptions.BaseError` *and* :exc:`ValueError`,
        so the difference is invisible to ``except BaseError`` and ``except
        ValueError``, and no call of this function or of a ``_make_*`` in the
        library sits inside an ``except`` for either one specifically.

    .. versionadded:: 1.5.0

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
