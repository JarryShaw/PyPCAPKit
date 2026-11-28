# -*- coding: utf-8 -*-
"""data models shared by the BOOTP and DHCP family

The flags and the options are encoded alike in a BOOTP and a DHCP message, so
:class:`~pcapkit.protocols.application.bootp.protocol.BOOTP` and
:class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4` share them. Each
:class:`OptionData` subclass is the structure one or more option codes carry, its
fields named as its specification names them.

.. versionadded:: 1.10.0

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Network
    from typing import Optional, Union

    from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
    from pcapkit.const.dhcp.message_type import MessageType as Enum_MessageType
    from pcapkit.const.dhcp.option import Option as Enum_Option
    from pcapkit.const.dhcp.relay_agent_suboption import \
        RelayAgentSubOption as Enum_RelayAgentSubOption

__all__ = [
    'Flags', 'Option', 'OverloadedField', 'DomainName', 'OptionData',
    'Address', 'Addresses', 'Number', 'Boolean', 'Text', 'Sizes', 'ArchitectureTypes',
    'AddressMask', 'PolicyFilter', 'Route', 'StaticRoutes', 'NodeType', 'Overload',
    'MessageType', 'ParameterList', 'ClientIdentifier', 'UserClass',
    'FQDNFlags', 'ClientFQDN', 'RelayAgentSubOption', 'RelayAgentInformation',
    'ClientNDI', 'MachineIdentifier', 'DomainSearch', 'ClasslessRoute',
    'ClasslessStaticRoutes', 'VendorClassEntry', 'VendorClass', 'VendorOption',
    'VendorOptions', 'VendorSpecific',
]


@info_final
class Flags(Data):
    """Data model for the header flags (:rfc:`1542#section-3.1.1`, :rfc:`2131#section-2`)."""

    #: Broadcast flag, the leftmost bit.
    broadcast: 'bool'
    #: The other 15 bits, which must be zero, as captured.
    reserved: 'int'

    if TYPE_CHECKING:
        def __init__(self, broadcast: 'bool', reserved: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


class OptionData(Data):
    """Data model for the decoded data of an option."""


@info_final
class Option(Data):
    """Data model for an option (:rfc:`2132#section-2`).

    :attr:`data` holds the decoded data where the option's parser registers a
    decoder for :attr:`code` and reads it exactly, and the raw octets otherwise.

    """

    #: Option code.
    code: 'Enum_Option'
    #: Length octet, or :obj:`None` for the Pad and End options, which have none.
    length: 'Optional[int]'
    #: Data, decoded or as raw octets; :obj:`None` for the Pad and End options.
    data: 'Optional[Union[OptionData, bytes]]'

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_Option', length: 'Optional[int]',
                     data: 'Optional[Union[OptionData, bytes]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class OverloadedField(Data):
    """Data model for an ``sname`` or ``file`` field holding options
    (:rfc:`2131#section-4.1`, :rfc:`2132#section-9.3`)."""

    #: The options, from the first octet of the field.
    options: 'tuple[Option, ...]'
    #: Octets after the End option, the Pad options filling the field, or from
    #: the option the field ends inside.
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, options: 'tuple[Option, ...]', padding: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class DomainName(Data):
    """Data model for a domain name (:rfc:`1035#section-3.1`).

    :attr:`literal` and :attr:`pointer` record how the name was written, so
    that it is rebuilt with the compression it was read with
    (:rfc:`1035#section-4.1.4`).

    """

    #: Name in presentation form, absolute, e.g. ``example.com.``.
    name: 'str'
    #: Every label of the name, the root's empty label left out.
    labels: 'tuple[bytes, ...]'
    #: How many of :attr:`labels` are written in full where the name is.
    literal: 'int'
    #: Offset of the compression pointer ending the name, or :obj:`None`
    #: where the root label ends it.
    pointer: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, name: 'str', labels: 'tuple[bytes, ...]', literal: 'int',
                     pointer: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Address(OptionData):
    """Data model for an option carrying one IPv4 address."""

    #: The address.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, address: 'IPv4Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Addresses(OptionData):
    """Data model for an option carrying a list of IPv4 addresses."""

    #: The addresses, in order of preference.
    addresses: 'tuple[IPv4Address, ...]'

    if TYPE_CHECKING:
        def __init__(self, addresses: 'tuple[IPv4Address, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Number(OptionData):
    """Data model for an option carrying one integer."""

    #: The integer, signed for the Time Offset option (:rfc:`2132#section-3.4`).
    value: 'int'

    if TYPE_CHECKING:
        def __init__(self, value: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Boolean(OptionData):
    """Data model for an option carrying an octet of ``0`` or ``1``."""

    #: Whether the octet is ``1``.
    value: 'bool'

    if TYPE_CHECKING:
        def __init__(self, value: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Text(OptionData):
    """Data model for an option carrying ASCII text (:rfc:`2132#section-2`)."""

    #: The text, with any trailing NUL kept.
    text: 'str'

    if TYPE_CHECKING:
        def __init__(self, text: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Sizes(OptionData):
    """Data model for the Path MTU Plateau Table option (:rfc:`2132#section-4.7`)."""

    #: MTU sizes, smallest first.
    sizes: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, sizes: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class AddressMask(Data):
    """Data model for an address and mask pair of the Policy Filter option."""

    #: Destination address.
    address: 'IPv4Address'
    #: Its mask.
    mask: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, address: 'IPv4Address', mask: 'IPv4Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class PolicyFilter(OptionData):
    """Data model for the Policy Filter option (:rfc:`2132#section-4.3`)."""

    #: Address and mask pairs.
    filters: 'tuple[AddressMask, ...]'

    if TYPE_CHECKING:
        def __init__(self, filters: 'tuple[AddressMask, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Route(Data):
    """Data model for a destination and router pair of the Static Route option."""

    #: Destination address.
    destination: 'IPv4Address'
    #: Router.
    router: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, destination: 'IPv4Address', router: 'IPv4Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class StaticRoutes(OptionData):
    """Data model for the Static Route option (:rfc:`2132#section-5.8`)."""

    #: Destination and router pairs, in order of priority.
    routes: 'tuple[Route, ...]'

    if TYPE_CHECKING:
        def __init__(self, routes: 'tuple[Route, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class NodeType(OptionData):
    """Data model for the NetBIOS over TCP/IP Node Type option (:rfc:`2132#section-8.7`)."""

    #: Node type, ``0x1`` for a B-node, ``0x2`` P-node, ``0x4`` M-node or ``0x8`` H-node.
    node_type: 'int'

    if TYPE_CHECKING:
        def __init__(self, node_type: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Overload(OptionData):
    """Data model for the Option Overload option (:rfc:`2132#section-9.3`)."""

    #: Whether the ``file`` field holds options, value ``1`` or ``3``.
    file: 'bool'
    #: Whether the ``sname`` field holds options, value ``2`` or ``3``.
    sname: 'bool'

    if TYPE_CHECKING:
        def __init__(self, file: 'bool', sname: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class MessageType(OptionData):
    """Data model for the DHCP Message Type option (:rfc:`2132#section-9.6`)."""

    #: Message type.
    type: 'Enum_MessageType'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_MessageType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class ParameterList(OptionData):
    """Data model for the Parameter Request List option (:rfc:`2132#section-9.8`)."""

    #: Option codes requested, in order of preference.
    codes: 'tuple[Enum_Option, ...]'

    if TYPE_CHECKING:
        def __init__(self, codes: 'tuple[Enum_Option, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ClientIdentifier(OptionData):
    """Data model for the Client-identifier option (:rfc:`2132#section-9.14`)."""

    #: Hardware type (:rfc:`1700`), or ``0`` for an identifier other than a
    #: hardware address.
    type: 'Enum_Hardware'
    #: Identifier; for an Ethernet type and six octets, a MAC address.
    identifier: 'Union[str, bytes]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Hardware', identifier: 'Union[str, bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class UserClass(OptionData):
    """Data model for the User Class option (:rfc:`3004#section-4`)."""

    #: Each instance of user class data.
    classes: 'tuple[bytes, ...]'

    if TYPE_CHECKING:
        def __init__(self, classes: 'tuple[bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class FQDNFlags(Data):
    """Data model for the flags of the Client FQDN option (:rfc:`4702#section-2.1`)."""

    #: ``N`` flag, set where the server should perform no DNS update.
    n: 'bool'
    #: ``E`` flag, set where the name is in canonical wire format, not ASCII.
    e: 'bool'
    #: ``O`` flag, set where the server has overridden the client's ``S`` flag.
    o: 'bool'
    #: ``S`` flag, set where the server should perform the A RR update.
    s: 'bool'
    #: ``MBZ``, the four high bits, which must be zero, as captured.
    mbz: 'int'

    if TYPE_CHECKING:
        def __init__(self, n: 'bool', e: 'bool', o: 'bool', s: 'bool', mbz: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ClientFQDN(OptionData):
    """Data model for the Client FQDN option (:rfc:`4702#section-2`)."""

    #: Flags.
    flags: 'FQDNFlags'
    #: ``RCODE1``, deprecated.
    rcode1: 'int'
    #: ``RCODE2``, deprecated.
    rcode2: 'int'
    #: Domain name, in presentation form where the ``E`` flag sets canonical wire
    #: format, ending in ``.`` where it is fully qualified, and else its ASCII
    #: text (:rfc:`4702#section-2.3`).
    name: 'str'

    if TYPE_CHECKING:
        def __init__(self, flags: 'FQDNFlags', rcode1: 'int', rcode2: 'int', name: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class RelayAgentSubOption(Data):
    """Data model for a sub-option of the Relay Agent Information option."""

    #: Sub-option code.
    code: 'Enum_RelayAgentSubOption'
    #: Length octet.
    length: 'int'
    #: Sub-option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_RelayAgentSubOption', length: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class RelayAgentInformation(OptionData):
    """Data model for the Relay Agent Information option (:rfc:`3046#section-2.0`)."""

    #: Sub-options, in order.
    suboptions: 'tuple[RelayAgentSubOption, ...]'

    if TYPE_CHECKING:
        def __init__(self, suboptions: 'tuple[RelayAgentSubOption, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ArchitectureTypes(OptionData):
    """Data model for the Client System Architecture Type option (:rfc:`4578#section-2.1`)."""

    #: Processor architecture types, in order of preference.
    types: 'tuple[int, ...]'

    if TYPE_CHECKING:
        def __init__(self, types: 'tuple[int, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ClientNDI(OptionData):
    """Data model for the Client Network Interface Identifier option (:rfc:`4578#section-2.2`)."""

    #: Interface type, ``1`` for UNDI.
    type: 'int'
    #: Major revision.
    major: 'int'
    #: Minor revision.
    minor: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'int', major: 'int', minor: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class MachineIdentifier(OptionData):
    """Data model for the Client Machine Identifier option (:rfc:`4578#section-2.3`)."""

    #: Identifier type, ``0`` for a GUID.
    type: 'int'
    #: The 16-octet identifier.
    identifier: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'int', identifier: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class DomainSearch(OptionData):
    """Data model for the Domain Search option (:rfc:`3397#section-2`)."""

    #: Domain names, in order.
    names: 'tuple[DomainName, ...]'

    if TYPE_CHECKING:
        def __init__(self, names: 'tuple[DomainName, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ClasslessRoute(Data):
    """Data model for a route of the Classless Static Route option."""

    #: Destination network.
    destination: 'IPv4Network'
    #: Router.
    router: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, destination: 'IPv4Network', router: 'IPv4Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ClasslessStaticRoutes(OptionData):
    """Data model for the Classless Static Route option (:rfc:`3442#section-2`)."""

    #: Routes, in order.
    routes: 'tuple[ClasslessRoute, ...]'

    if TYPE_CHECKING:
        def __init__(self, routes: 'tuple[ClasslessRoute, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class VendorClassEntry(Data):
    """Data model for one vendor's data in the Vendor-Identifying Vendor Class option."""

    #: IANA Private Enterprise Number.
    enterprise: 'int'
    #: Each item of the vendor class data.
    classes: 'tuple[bytes, ...]'

    if TYPE_CHECKING:
        def __init__(self, enterprise: 'int', classes: 'tuple[bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class VendorClass(OptionData):
    """Data model for the Vendor-Identifying Vendor Class option (:rfc:`3925#section-3`)."""

    #: Each vendor's data.
    vendors: 'tuple[VendorClassEntry, ...]'

    if TYPE_CHECKING:
        def __init__(self, vendors: 'tuple[VendorClassEntry, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class VendorOption(Data):
    """Data model for a sub-option of the Vendor-Identifying Vendor-Specific Information option."""

    #: Sub-option code, the vendor's own.
    code: 'int'
    #: Sub-option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'int', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class VendorOptions(Data):
    """Data model for one vendor's data in the Vendor-Identifying Vendor-Specific Information option."""

    #: IANA Private Enterprise Number.
    enterprise: 'int'
    #: The vendor's sub-options.
    options: 'tuple[VendorOption, ...]'

    if TYPE_CHECKING:
        def __init__(self, enterprise: 'int', options: 'tuple[VendorOption, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class VendorSpecific(OptionData):
    """Data model for the Vendor-Identifying Vendor-Specific Information option
    (:rfc:`3925#section-4`)."""

    #: Each vendor's data.
    vendors: 'tuple[VendorOptions, ...]'

    if TYPE_CHECKING:
        def __init__(self, vendors: 'tuple[VendorOptions, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
