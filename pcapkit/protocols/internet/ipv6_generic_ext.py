# -*- coding: utf-8 -*-
"""IPv6_GenericExt - Generic IPv6 Extension Header
======================================================

.. module:: pcapkit.protocols.internet.ipv6_generic_ext

:mod:`pcapkit.protocols.internet.ipv6_generic_ext` contains
:class:`~pcapkit.protocols.internet.ipv6_generic_ext.IPv6_GenericExt`
only, which implements a **generic** extractor for IPv6 extension
headers, standing in for one whenever the header's own dedicated
parser is unavailable or has failed.

Why this is safe in general
----------------------------

:rfc:`6564#section-4` is Standards Track and says, with an RFC 2119
**MUST**, that any IPv6 extension header defined from April 2012
onward carries the same first two octets:

======= ========= ===================== =====================================
Octets      Bits        Name                    Description
======= ========= ===================== =====================================
  0           0   ``next``                    Next Header
  1           8   ``len``                     Hdr Ext Len (8-octet units,
                                                excluding the first 8 octets)
  2          16   ``payload``                 Header-specific content
======= ========= ===================== =====================================

so the first two octets of a *conforming* header are parseable without
knowing anything else about it. :rfc:`6564#section-5` is explicit that
this is **not retroactive** -- *"[i]t applies only to newly defined
extension headers"* -- which is why the pre-existing headers need the
closed exception table below rather than being assumed to conform.
(:rfc:`8200#section-4.8` restates the same layout, but without a MUST,
and mislabels the generic length field as *"Length of the Destination
Options header"*; cite :rfc:`6564#section-4`, not that section.)

The exception table, verified against IANA's ``protocol-numbers-1.csv``
*IPv6 Extension Header* column and each cited RFC:

======================================================= ===========================================
Header(s)                                                Length rule
======================================================= ===========================================
``HOPOPT``, ``IPv6-Route``, ``IPv6-Opts``, ``MH``,       ``(octet[1] + 1) * 8`` -- the :rfc:`6564`
``HIP``, ``Shim6``                                       generic rule
``IPv6-Frag``                                            constant ``8``; octet[1] is Reserved, not a
                                                          length (:rfc:`8200#section-4.5`)
``AH``                                                   ``(octet[1] + 2) * 4`` -- :rfc:`4302#section-2.2`
                                                          counts in 4-octet units with a bias of 2,
                                                          not :rfc:`6564`'s 8-octet units and bias of 1
``ESP``                                                  terminal -- has a dedicated, registered parser
                                                          (:class:`~pcapkit.protocols.internet.esp.ESP`),
                                                          but its Next Header byte is inside the
                                                          encrypted trailer (:rfc:`4303`), so its own
                                                          info's ``next`` is :data:`None` rather than a
                                                          value to continue on
``BIT-EMU``, ``253``, ``254``                            terminal -- no dedicated parser exists, so no
                                                          next header field is ever read at all, either
======================================================= ===========================================

This table classifies all twelve IANA-registered codes by *wire format*
alone. ``Shim6`` conforms to it (:rfc:`5533`), but this package has never
had a dedicated parser class for it to begin with -- see "Two entry paths"
below for how it reaches this class regardless, by direct dispatch rather
than by a parser of its own failing.

:rfc:`8200#section-4.5` says outright that Encapsulating Security
Payload *"is not considered an extension header"*; :rfc:`4303` puts its
Next Header inside the encrypted trailer, with no length field anywhere
in the cleartext part; and 253/254 are reserved for private
experimentation (:rfc:`3692`) with no wire format at all. None of the
four is reachable through this class, by construction -- see
:meth:`pcapkit.protocols.internet.ipv6.IPv6._import_next_layer`. Each of
them still enters :meth:`IPv6._decode_next_layer
<pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`'s walk (it is a
real :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` member),
but the four part ways there: ``ESP`` resolves to its own dedicated parser,
whose info carries a ``next`` that is simply :data:`None` -- so the walk
ends the ordinary way, ``ExtensionHeader(None)`` failing at the top of the
next iteration, exactly as it did before this class existed. ``BIT-EMU``,
``253`` and ``254`` have no dedicated parser and resolve to plain
:class:`~pcapkit.protocols.misc.raw.Raw`, whose info has no ``next``
*attribute* at all; for these three (and any future IANA code nobody has
implemented yet) the walk stops on a *structural* check -- does the parsed
layer carry a ``next`` at all? -- rather than on a list of codes.

Two entry paths
----------------

This class is reached two different ways:

1. **An unrecognised protocol number.** :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6`
   is a real IANA extension header (:rfc:`5533`) that this package has never
   had a dedicated parser for, so
   :meth:`pcapkit.protocols.internet.internet.Internet._lookup_next_layer`
   used to default it to plain :class:`~pcapkit.protocols.misc.raw.Raw` --
   which has no ``next`` field, so the walk in
   :meth:`IPv6._decode_next_layer <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`
   crashed on it (GitHub issue #891). This module registers itself for that
   code instead (see the bottom of the module), so dispatch reaches a
   working generic parser directly. That registration is global -- shared
   by every :class:`~pcapkit.protocols.internet.internet.Internet`
   subclass -- so :meth:`__post_init__` gates on ``version == 6`` to keep
   it from also activating for an IPv4 payload that happens to carry
   protocol number 140; see its docstring for what that would otherwise do.
2. **A recognised header whose own parser raises.** This is the actual #891
   defect: ``HOPOPT``, ``IPv6-Route``, ``IPv6-Opts``, ``MH``, ``HIP``,
   ``IPv6-Frag`` and ``AH`` all have dedicated classes, and when one of
   *those* raises, :func:`~pcapkit.utilities.decorators.beholder`
   (:meth:`Protocol._import_next_layer <pcapkit.protocols.protocol.ProtocolBase._import_next_layer>`)
   would ordinarily catch it and substitute plain
   :class:`~pcapkit.protocols.misc.raw.Raw` -- which loses the ``next``
   field the same way, and crashes the walk exactly as Shim6 did.
   :meth:`IPv6._import_next_layer <pcapkit.protocols.internet.ipv6.IPv6._import_next_layer>`
   catches that failure itself, one layer in from ``beholder``, and
   substitutes this class instead: the bad header costs only itself, not
   the rest of the chain.

The overrun guard
-------------------

The house convention for a declared length that does not fit what remains
is warn-and-clip: emit a :class:`~pcapkit.utilities.warnings.SchemaWarning`
naming what was declared against what is left, then read only what is
left --

* :func:`pcapkit.protocols.schema.misc.pcapng.bounded_option`
  (``pcapkit/protocols/schema/misc/pcapng.py:373``)
* :func:`pcapkit.protocols.schema.misc.pcapng.bounded_area`
  (``pcapkit/protocols/schema/misc/pcapng.py:443``)
* :meth:`pcapkit.corekit.fields.field.FieldBase.pack <pcapkit.corekit.fields.field.FieldBase>`
  (``pcapkit/corekit/fields/field.py:507``)
* :meth:`pcapkit.protocols.misc.pcapng.PCAPNG.read_frame`
  (``pcapkit/protocols/misc/pcapng.py:1119``)

This class follows that convention's *warning* and deliberately diverges on
the *action*. Clipping is right when the declared length only governs how
much of the current object to read -- there is always a well-defined "what
is left" to fall back to. Here, the declared length also decides *where the
next header starts*; a clipped skip distance points at whatever bytes
happen to be at the end of the buffer, which are not a header. Continuing
the walk from there would fabricate a layer and record a false entry in
:class:`~pcapkit.corekit.protochain.ProtoChain`, which reads as a parsed
fact rather than as the guess it would be. So :meth:`read` below warns in
the same wording as the sites above, then **stops the walk**: this instance
absorbs every remaining octet and reports :data:`None` for ``next``, which
is what the caller's loop already reads as "no more extension headers" and
ends on honestly, at the bad header, instead of inventing what follows it.

"""
from typing import TYPE_CHECKING, overload

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.ipv6_generic_ext import IPv6_GenericExt as Data_IPv6_GenericExt
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.ipv6_generic_ext import \
    IPv6_GenericExt as Schema_IPv6_GenericExt
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall, stacklevel
from pcapkit.utilities.warnings import SchemaWarning, warn

if TYPE_CHECKING:
    from typing import IO, Any, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['IPv6_GenericExt']


class IPv6_GenericExt(Internet[Data_IPv6_GenericExt, Schema_IPv6_GenericExt],
                      schema=Schema_IPv6_GenericExt, data=Data_IPv6_GenericExt):
    """This class implements a generic IPv6 extension header parser.

    See the module docstring for the RFC citations backing the length
    rules below, the two ways this class gets dispatched to, and the
    reasoning for stopping rather than clipping on an overrun.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Generic IPv6 Extension Header"]':
        """Name of current protocol."""
        return 'Generic IPv6 Extension Header'

    @property
    def alias(self) -> 'Literal["IPv6-GenericExt"]':
        """Acronym of corresponding protocol.

        Hyphenated, like :attr:`IPv6_Frag.alias
        <pcapkit.protocols.internet.ipv6_frag.IPv6_Frag.alias>` and
        :attr:`IPv6_Opts.alias <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.alias>`,
        and for the same reason: :meth:`IPv6._decode_next_layer
        <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>` builds the
        packet-dict key by ``self.alias.lstrip('IPv6-').lower()`` --
        :meth:`str.lstrip` strips a character *set*, not a prefix, so the
        default (class-name) alias ``'IPv6_GenericExt'`` would strip to
        ``'_GenericExt'`` and key the dict as ``_genericext``. The hyphen
        makes every leading character (``I``, ``P``, ``v``, ``6``, ``-``) a
        member of the set being stripped, same as the siblings, giving
        ``genericext``.

        """
        return 'IPv6-GenericExt'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def protocol(self) -> 'Optional[Enum_ExtensionHeader]':
        """The extension header this instance stands in for.

        This is **not** the base :attr:`Protocol.protocol
        <pcapkit.protocols.protocol.ProtocolBase.protocol>` meaning ("name
        of next layer protocol"); it is deliberately repointed, on the
        owner's ruling for GitHub issue #891, at this instance's *own*
        identity -- which header's format it parsed, e.g.
        :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.HOPOPT`
        or :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6`.
        That identity is resolved per instance from the numeric code handed
        to the constructor (``alias``), which
        :meth:`pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer`
        already holds before it dispatches (``ipv6.py:327``). See
        :meth:`__index__` for why the *class-level* identity cannot be
        made to work the same way.

        """
        return self._info.protocol

    @property
    def next(self) -> 'Optional[Enum_TransType]':
        """Next header, as parsed off the wire.

        :data:`None` when the declared length would have overrun what
        remained of the chain and the walk stopped instead of trusting it
        -- see the module docstring's "overrun guard" section.

        """
        return self._info.next

    @property
    def payload(self) -> 'ProtocolBase | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return self._next

    @property
    def protochain(self) -> 'ProtoChain | NoReturn':
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protochain'")
        return super().protochain

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, error: 'Optional[Exception]' = None,
             alias: 'Optional[int]' = None, version: 'Literal[4, 6]' = 6,  # pylint: disable=arguments-differ,unused-argument
             extension: 'bool' = False, **kwargs: 'Any') -> 'Data_IPv6_GenericExt':  # pylint: disable=unused-argument
        """Read a generically-parsed IPv6 extension header.

        Args:
            length: Length of packet data.
            error: Parsing error, if reached as a
                :func:`~pcapkit.utilities.decorators.beholder` fallback.
            alias: Numeric extension header code this instance stands in
                for, e.g. ``0`` for ``HOPOPT`` or ``140`` for ``Shim6``.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        ext_code = None  # type: Optional[Enum_ExtensionHeader]
        if alias is not None:
            try:
                ext_code = Enum_ExtensionHeader(alias)
            except ValueError:
                ext_code = None

        if ext_code == Enum_ExtensionHeader.IPv6_Frag:
            # RFC 8200 §4.5: octet 1 is Reserved, not a length -- the
            # fragment header is always exactly 8 octets, and RFC 6564 §5
            # says explicitly that it predates and does not follow the
            # generic format.
            nominal = 8
        elif ext_code == Enum_ExtensionHeader.AH:
            # RFC 4302 §2.2: Payload Len is in 4-octet units, excluding the
            # first 8 octets -- a different unit and a different bias from
            # RFC 6564's Hdr Ext Len.
            nominal = (schema.len + 2) * 4
        else:
            # RFC 6564 §4 (MUST): Hdr Ext Len is in 8-octet units,
            # excluding the first 8 octets. Also the fallback when ``alias``
            # named no known extension header at all, which is the best
            # generic guess available.
            nominal = (schema.len + 1) * 8

        if nominal > length:
            # See the module docstring's "overrun guard" section for why
            # this warns like the house convention but stops rather than
            # clips.
            warn(f'IPv6: extension header declares a length of {nominal} octet(s) with '
                 f'{length} octet(s) left in the chain; stopping the walk instead of '
                 f'skipping past it', SchemaWarning, stacklevel=stacklevel())
            ext_len = length
            next_header = None  # type: Optional[Enum_TransType]
        else:
            ext_len = nominal
            next_header = schema.next

        generic_ext = Data_IPv6_GenericExt(
            protocol=ext_code,
            next=next_header,
            length=ext_len,
            error=error,
        )

        if extension:
            return generic_ext
        return self._decode_next_layer(generic_ext, next_header, length - ext_len)

    def make(self,
             next: 'Enum_TransType | int' = Enum_TransType.UDP,  # pylint: disable=redefined-builtin
             len: 'int' = 0,  # pylint: disable=redefined-builtin
             payload: 'bytes | ProtocolBase | Any' = b'',
             **kwargs: 'Any') -> 'Schema_IPv6_GenericExt':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            len: Raw ``Hdr Ext Len`` octet to emit -- the caller's
                responsibility to size correctly, since this class does not
                know, at construction time, which per-protocol rule (see
                the module docstring) the octet is meant to satisfy.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        return Schema_IPv6_GenericExt(
            next=next,
            len=len,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      version: 'Literal[4, 6]' = ..., extension: 'bool' = ...,
                      **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      version: 'Literal[4, 6]' = 6, extension: 'bool' = False,
                      **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            version: IP protocol version.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            ProtocolError: If ``version`` is not ``6``.

        See Also:
            For construction argument, please refer to :meth:`make`.

        Note:
            This class is registered into :attr:`Internet.__proto__
            <pcapkit.protocols.internet.internet.Internet.__proto__>` --
            shared by *every* :class:`~pcapkit.protocols.internet.internet.Internet`
            subclass, :class:`~pcapkit.protocols.internet.ipv4.IPv4` included --
            so that :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6`
            resolves to a working parser instead of defaulting to
            :class:`~pcapkit.protocols.misc.raw.Raw`. Without this guard, an
            IPv4 packet whose protocol byte happens to be 140 would reach
            this class too and walk an IPv6-style extension-header chain out
            of an IPv4 payload -- verified: it would read
            ``IPv4:IPv6-GenericExt:...`` instead of the ``IPv4:Shim6`` a
            plain, non-continuing ``Raw`` gives today. Rejecting here sends
            construction back through :func:`~pcapkit.utilities.decorators.beholder`
            at the *caller's* layer, which substitutes that same ``Raw`` --
            i.e. this restores exactly the pre-existing, version-agnostic
            behaviour rather than inventing a new one, and needs no
            IPv4-specific code of its own.

        """
        if version != 6:
            raise ProtocolError(
                f'{self.__class__.__name__}: only valid for IPv6, got version={version}')

        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, version=version, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'Literal[2]':
        """Return an estimated length for the object."""
        return 2

    @classmethod
    def __index__(cls) -> 'NoReturn':
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no *class-level* registry
                entry. Unlike :meth:`Raw.__index__
                <pcapkit.protocols.misc.raw.Raw.__index__>`, which raises
                because :class:`~pcapkit.protocols.misc.raw.Raw` has no
                identity to report at all, this class *does* have one --
                see :attr:`protocol` -- but it is resolved per instance,
                not per class: one :class:`IPv6_GenericExt` stands in for
                :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.HOPOPT`,
                :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6`
                and any other RFC 6564-conforming code alike, while
                :meth:`__index__` is a ``@classmethod`` with nowhere to put
                a value that differs per instance.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPv6_GenericExt') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Inverts whichever per-protocol length rule :meth:`read` applied,
        using ``data.protocol`` -- the extension header this instance stood
        in for -- to pick the same rule back. Round-tripping a ``data.next``
        of :data:`None` (the overrun case) is not supported: there is no
        octet value that both satisfies the rule and still fits, which is
        exactly why :meth:`read` stopped rather than clipped.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        if data.protocol == Enum_ExtensionHeader.IPv6_Frag:
            len_octet = 0  # constant length; the octet itself is Reserved
        elif data.protocol == Enum_ExtensionHeader.AH:
            len_octet = data.length // 4 - 2
        else:
            len_octet = data.length // 8 - 1

        return {
            'next': data.next,
            'len': len_octet,
            'payload': cls._make_payload(data),
        }


# NOTE: Registered by direct assignment into ``Internet.__proto__`` -- the
# same mechanism ``pcapkit.protocols.internet.internet`` uses to pre-populate
# every other entry -- rather than via the ``code=`` keyword of
# ``ProtocolBase.__init_subclass__``. The two are equivalent in effect, but
# ``code=`` resolves through ``register_protocol_code``, which imports
# ``pcapkit.foundation.registry.protocols`` *at class-definition time*, i.e.
# while ``pcapkit.protocols.internet`` (which imports this module) is still
# being built. Nothing else in this package's ``code=`` usage does that from
# inside ``pcapkit.protocols.internet`` itself, and doing so here completed a
# cycle back into a not-yet-finished ``pcapkit.protocols.internet`` through
# ``pcapkit.foundation.extraction`` -- measured as ``ImportError: cannot
# import name 'Extractor' from partially initialized module
# 'pcapkit.foundation.extraction'`` on a bare ``import pcapkit``. Plain
# dict assignment carries no import of its own, so it cannot re-trigger that.
Internet.__proto__[Enum_TransType.Shim6] = IPv6_GenericExt
