# -*- coding: utf-8 -*-
"""IPv6_Ext - IPv6 Extension Header
====================================

.. module:: pcapkit.protocols.internet.ipv6_ext

:mod:`pcapkit.protocols.internet.ipv6_ext` contains
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
only, which serves two roles (GitHub issue :issue:`917`): the shared
**base class** of every IPv6 extension header in this package, and a
**generic** extractor that stands in for a header whose dedicated parser is
unavailable or has failed. The class docstring divides the two.

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
this is **not retroactive** -- it applies only to newly defined extension
headers -- which is why the pre-existing headers need the closed exception
table below rather than being assumed to conform. (:rfc:`8200#section-4.8`
restates the layout without a MUST and mislabels the generic length field as
the length of the Destination Options header; cite :rfc:`6564#section-4`
instead.)

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
``253``, ``254``                                         terminal -- no dedicated parser exists, so no
                                                          next header field is ever read at all, either
======================================================= ===========================================

This table classifies by *wire format* alone, over the eleven codes
:class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` enumerates,
which match IANA's *IPv6 Extension Header Types* registry exactly (GitHub
issue :issue:`925`).

``Shim6`` conforms to it (:rfc:`5533`) but has no dedicated parser class; see
"Two entry paths" below for how it reaches this class by direct dispatch.

:rfc:`8200#section-4.5` sets Encapsulating Security Payload aside: ESP is not
an extension header, and the RFC lists it among upper-layer headers.
:rfc:`4303` puts its Next Header inside the encrypted trailer, with no length
field in the cleartext part. 253 and 254 are reserved for private
experimentation (:rfc:`3692`) with no wire format at all. None of the three
is reachable through this class, by construction; see
:meth:`pcapkit.protocols.internet.ipv6.IPv6._import_next_layer`. Each still
enters :meth:`IPv6._decode_next_layer
<pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`'s walk, being a
real :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` member, but
they part ways there. ``ESP`` resolves to its own dedicated parser, whose info
carries a ``next`` of :data:`None`, so the walk ends the ordinary way with
``ExtensionHeader(None)`` failing at the top of the next iteration. ``253``
and ``254`` have no dedicated parser and resolve to plain
:class:`~pcapkit.protocols.misc.raw.Raw`, whose info has no ``next``
*attribute*. For these two, and any future IANA code without an
implementation, the walk stops on a *structural* check (does the parsed layer
carry a ``next`` at all?) rather than on a list of codes.

Two entry paths
----------------

This class is reached two different ways:

1. **An unrecognised protocol number.** :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6`
   is a real IANA extension header (:rfc:`5533`) with no dedicated parser, so
   :meth:`pcapkit.protocols.internet.internet.Internet._lookup_next_layer`
   would default it to plain :class:`~pcapkit.protocols.misc.raw.Raw`. That
   has no ``next`` field, so the walk in
   :meth:`IPv6._decode_next_layer <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`
   would crash on it (GitHub issue :issue:`891`). This module registers itself
   for that code instead (see the bottom of the module), so dispatch reaches a
   working generic parser directly. The registration is global, shared by
   every :class:`~pcapkit.protocols.internet.internet.Internet` subclass, so
   :meth:`__post_init__` gates on ``version == 6`` to keep it from also
   activating for an IPv4 payload that carries protocol number 140; see its
   docstring.
2. **A recognised header whose own parser raises.** ``HOPOPT``,
   ``IPv6-Route``, ``IPv6-Opts``, ``MH``, ``HIP``, ``IPv6-Frag`` and ``AH`` all
   have dedicated classes. When one of *those* raises,
   :func:`~pcapkit.utilities.decorators.beholder`
   (:meth:`Protocol._import_next_layer <pcapkit.protocols.protocol.ProtocolBase._import_next_layer>`)
   would substitute plain :class:`~pcapkit.protocols.misc.raw.Raw`, which loses
   ``next`` and crashes the walk as in path 1.
   :meth:`IPv6._import_next_layer <pcapkit.protocols.internet.ipv6.IPv6._import_next_layer>`
   catches the failure itself, one layer in from ``beholder``, and substitutes
   this class: the bad header costs only itself, not the rest of the chain.

The overrun guard
-------------------

The house convention for a declared length that does not fit what remains
is warn-and-clip: emit a warning naming what was declared against what is
left, then read only what is left. See
:func:`pcapkit.protocols.schema.misc.pcapng.bounded_option`,
:func:`pcapkit.protocols.schema.misc.pcapng.bounded_area` and
:meth:`pcapkit.protocols.misc.pcapng.PCAPNG.read`.

This class follows that convention's *warning*
(:class:`~pcapkit.utilities.warnings.SchemaWarning`) and deliberately diverges
on the *action*. Clipping is right when the declared length only governs how
much of the current object to read, since there is always a well-defined
"what is left" to fall back to. Here the declared length also decides *where
the next header starts*; a clipped skip distance points at whatever bytes
end the buffer, which are not a header. Continuing from there would
fabricate a layer and record a false entry in
:class:`~pcapkit.corekit.protochain.ProtoChain`, which reads as a parsed fact
rather than a guess. So :meth:`read` warns in the same wording as the sites
above, then **stops the walk**: this instance absorbs every remaining octet
and reports :data:`None` for ``next``, which the caller's loop already reads
as "no more extension headers". The chain ends honestly at the bad header
instead of inventing what follows it.

"""
from typing import TYPE_CHECKING, Generic, cast, overload

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.ipv6_ext import IPv6_Ext as Data_IPv6_Ext
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST, ProtocolBase
from pcapkit.protocols.schema.internet.ipv6_ext import IPv6_Ext as Schema_IPv6_Ext
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall, stacklevel
from pcapkit.utilities.warnings import SchemaWarning, warn

if TYPE_CHECKING:
    from typing import IO, Any, NoReturn, Optional, Protocol

    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain

    class _NextHeaderData(Protocol):
        """The one field every IPv6 extension header's data model carries.

        :rfc:`8200#section-4.1` puts a Next Header octet first in every
        extension header, and all eight implemented ones record it under this
        name -- which is what lets :attr:`IPv6_Ext.next` be a *shared* member
        rather than a fallback-role-only one. Narrower than
        :class:`~pcapkit.protocols.data.internet.ipv6_ext.IPv6_Ext` on
        purpose: ``length`` is deliberately absent, because
        :class:`~pcapkit.protocols.data.internet.ipv6_frag.IPv6_Frag` has no
        such field (its length is the constant 8, and its own
        :attr:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag.length`
        property supplies it).

        """

        next: 'Optional[Enum_TransType]'

__all__ = ['IPv6_Ext']


class IPv6_Ext(Internet[_PT, _ST], Generic[_PT, _ST],
               schema=Schema_IPv6_Ext, data=Data_IPv6_Ext):
    """This class implements a generic IPv6 extension header parser, and is
    the shared base of every IPv6 extension header in this package.

    The module docstring has the RFC citations behind the length rules, the two
    ways this class is dispatched to, and why an overrun stops the walk rather
    than clipping.

    The two roles
    --------------

    One class plays both, on the owner's ruling for GitHub issue :issue:`917`:

    1. **The concrete fallback parser** for an :rfc:`6564`-conforming header
       with no dedicated class, or whose dedicated class raised. :meth:`read`,
       :meth:`make`, :attr:`name`, :attr:`alias` and the ``schema=``/``data=``
       above implement it.
    2. **The base class** of the eight implemented extension headers
       (:class:`~pcapkit.protocols.internet.hopopt.HOPOPT`,
       :class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route`,
       :class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`,
       :class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`,
       :class:`~pcapkit.protocols.internet.hip.HIP`,
       :class:`~pcapkit.protocols.internet.mh.MH`,
       :class:`~pcapkit.protocols.internet.ah.AH` and
       :class:`~pcapkit.protocols.internet.esp.ESP`), which is what the
       ``_extf`` guards on :attr:`payload`, :attr:`protocol` and
       :attr:`protochain` are for.

    It is generic in its data and schema types, like
    :class:`~pcapkit.protocols.internet.ipsec.IPsec`, the other base in this
    package, so that a subclass keeps its *own* ``_PT``/``_ST`` instead of
    inheriting this class's. ``AH`` and ``ESP`` therefore double-inherit two
    identically-parameterised generic bases, ``IPsec[…]`` and ``IPv6_Ext[…]``.

    Warning:
        A subclass **must** define :attr:`name`, :attr:`alias`,
        :attr:`protocol`, :attr:`length` and :meth:`__index__` itself. All five
        carry this class's *fallback-role* answers, which are wrong for a
        header with an identity of its own: it would report itself as
        ``IPv6 Extension Header`` / ``IPv6-Ext``, read its length off a data
        model that is not its own, and :meth:`__index__` would raise rather
        than return its IANA number. The language cannot enforce the override,
        so ``tests/protocols/internet/test_ipv6_ext_unit.py`` does, over every
        subclass discovered at runtime.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Name of current protocol.

        Annotated ``str`` rather than the ``Literal`` every *leaf* protocol in
        this package uses, because this one is also a base: a ``Literal`` here
        makes each subclass's own ``Literal`` an incompatible override (mypy
        ``[override]``). The value is still the single fallback-role constant.

        """
        return 'IPv6 Extension Header'

    @property
    def alias(self) -> 'str':
        """Acronym of corresponding protocol.

        Annotated ``str`` rather than ``Literal``, for the reason given on
        :attr:`name`.

        Hyphenated, like :attr:`IPv6_Frag.alias
        <pcapkit.protocols.internet.ipv6_frag.IPv6_Frag.alias>` and
        :attr:`IPv6_Opts.alias <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts.alias>`,
        for the same reason: :meth:`IPv6._decode_next_layer
        <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>` builds the
        packet-dict key with ``self.alias.lstrip('IPv6-').lower()``, and
        :meth:`str.lstrip` strips a character *set*, not a prefix. The default
        (class-name) alias ``'IPv6_Ext'`` would strip to ``'_Ext'`` and key the
        dict as ``_ext``; the hyphen makes every leading character (``I``,
        ``P``, ``v``, ``6``, ``-``) part of the stripped set, giving ``ext``.

        """
        return 'IPv6-Ext'

    @property
    def length(self) -> 'int':
        """Header length of current protocol.

        Fallback-role member: it reads this module's *own* data model, so a
        subclass whose data model records its length elsewhere, or not at all
        (as :class:`~pcapkit.protocols.data.internet.ipv6_frag.IPv6_Frag`), must
        override it. All eight implemented headers do, and
        ``tests/protocols/internet/test_ipv6_ext_unit.py`` holds them to it.

        """
        return cast('Data_IPv6_Ext', self._info).length

    @property
    def protocol(self) -> 'Optional[Enum_ExtensionHeader] | Optional[str]':
        """The extension header this instance stands in for.

        In the *fallback* role (this instance parsed this module's own schema)
        this is **not** the base
        :attr:`Protocol.protocol <pcapkit.protocols.protocol.ProtocolBase.protocol>`
        meaning ("name of next layer protocol"). On the owner's ruling for
        GitHub issue :issue:`891` it is deliberately repointed at this
        instance's *own* identity, i.e. which header's format it parsed, such as
        :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.HOPOPT`
        or :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6`.
        The identity is resolved per instance from the numeric code handed to
        the constructor (``alias``), which
        :meth:`pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer` already
        holds before it dispatches. See :meth:`__index__` for why the
        *class-level* identity cannot work the same way. It is deliberately
        *not* ``_extf``-guarded in this role: that same call passes
        ``extension=True`` for every extension header in a chain, so guarding
        it would make the identity unreadable in exactly the case it exists for.

        In the *base* role it falls through to ``super()``, restoring the
        ordinary :class:`~pcapkit.protocols.protocol.ProtocolBase` meaning.
        That is load-bearing: all eight subclasses implement their own
        ``_extf``-guarded ``protocol`` as ``return super().protocol``, and this
        class sits between them and
        :class:`~pcapkit.protocols.protocol.ProtocolBase` in the MRO, so without
        the discriminator below each would read ``self._info.protocol`` off a
        data model with no such field (``AttributeError``).

        The discriminator is the *class-level*
        :attr:`~pcapkit.protocols.protocol.ProtocolBase.__data__` rather than an
        :func:`isinstance` test on ``self._info``, because a ``make``-only
        instance has no ``_info`` at all. Reading it would turn
        :attr:`ProtocolBase.protocol <pcapkit.protocols.protocol.ProtocolBase.protocol>`,
        which only needs ``self._protos``, into an ``AttributeError``;
        ``tests/protocols/internet/test_ipv6_extension_unit.py`` constructs
        exactly that instance.

        """
        if self.__data__ is Data_IPv6_Ext:
            return cast('Data_IPv6_Ext', self._info).protocol
        return super().protocol

    @property
    def next(self) -> 'Optional[Enum_TransType]':
        """Next header, as parsed off the wire.

        Shared by every subclass rather than fallback-role-only; see
        :class:`_NextHeaderData` for why that is sound.

        :data:`None` when the declared length would have overrun what remained
        of the chain and the walk stopped instead of trusting it; see the
        module docstring's "overrun guard" section.

        """
        return cast('_NextHeaderData', self._info).next

    @property
    def payload(self) -> 'ProtocolBase | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return super().payload

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

    def read(self, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
             extension: 'bool' = False, **kwargs: 'Any') -> '_PT':
        """Read a generically-parsed IPv6 extension header.

        Args:
            length: Length of packet data.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments, two of which are this
                class's own and are supplied by :meth:`IPv6._import_next_layer
                <pcapkit.protocols.internet.ipv6.IPv6._import_next_layer>`
                rather than typed by a caller:

                * ``alias`` -- the numeric extension header code this instance
                  stands in for, e.g. ``0`` for ``HOPOPT`` or ``140`` for
                  ``Shim6``.
                * ``error`` -- the parsing error, when this instance was
                  reached as a :func:`~pcapkit.utilities.decorators.beholder`
                  fallback rather than by direct dispatch.

        Returns:
            Parsed packet data.

        Note:
            Those two are read out of ``**kwargs`` rather than declared, and
            ``version`` is not declared either, because this class is *also*
            the base of eight subclasses whose own ``read`` accepts none of the
            three. Declaring them would assert of the whole family an interface
            only the fallback has, which mypy (``Signature of "read"
            incompatible with supertype``, ``[override]``) and pylint
            (``arguments-differ``) both reject. This method never reads
            ``version``; the version gate lives in :meth:`__post_init__`, which
            still takes it explicitly.

        """
        alias = kwargs.get('alias')  # type: Optional[int]
        error = kwargs.get('error')  # type: Optional[Exception]

        if length is None:
            length = len(self)
        schema = cast('Schema_IPv6_Ext', self.__header__)

        ext_code = None  # type: Optional[Enum_ExtensionHeader]
        if alias is not None:
            try:
                ext_code = Enum_ExtensionHeader(alias)
            except ValueError:
                ext_code = None

        if ext_code == Enum_ExtensionHeader.IPv6_Frag:
            # RFC 8200 §4.5: octet 1 is Reserved, not a length; the fragment
            # header is always exactly 8 octets, and RFC 6564 §5 says it predates
            # and does not follow the generic format.
            nominal = 8
        elif ext_code == Enum_ExtensionHeader.AH:
            # RFC 4302 §2.2: Payload Len is in 4-octet units, excluding the
            # first 8 octets: a different unit and bias from RFC 6564's
            # Hdr Ext Len.
            nominal = (schema.len + 2) * 4
        else:
            # RFC 6564 §4 (MUST): Hdr Ext Len is in 8-octet units, excluding
            # the first 8 octets. Also the best generic guess when ``alias``
            # named no known extension header.
            nominal = (schema.len + 1) * 8

        if nominal > length:
            # Warns like the house convention but stops rather than clips; see
            # the module docstring's "overrun guard" section.
            warn(f'IPv6: extension header declares a length of {nominal} octet(s) with '
                 f'{length} octet(s) left in the chain; stopping the walk instead of '
                 f'skipping past it', SchemaWarning, stacklevel=stacklevel())
            ext_len = length
            next_header = None  # type: Optional[Enum_TransType]
        else:
            ext_len = nominal
            next_header = schema.next

        # NOTE: The schema's payload holds every octet after the two fixed
        # ones; the first ``ext_len - 2`` of them are this header's own body.
        rest = schema.get_payload()
        generic_ext = Data_IPv6_Ext(
            protocol=ext_code,
            next=next_header,
            declared_next=schema.next,
            len=schema.len,
            length=ext_len,
            data=rest[:max(ext_len - 2, 0)],
            error=error,
        )

        if extension:
            return cast('_PT', generic_ext)
        return self._decode_next_layer(cast('_PT', generic_ext), next_header, length - ext_len,
                                       payload=rest[max(ext_len - 2, 0):])

    def make(self, *,
             next: 'Enum_TransType | int' = Enum_TransType.UDP,  # pylint: disable=redefined-builtin
             len: 'int' = 0,  # pylint: disable=redefined-builtin
             data: 'bytes' = b'',
             payload: 'bytes | ProtocolBase | Any' = b'',
             **kwargs: 'Any') -> '_ST':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            len: Raw ``Hdr Ext Len`` octet to emit. The caller must size it,
                since this class cannot know at construction time which
                per-protocol rule (see the module docstring) it must satisfy.
            data: Header-specific content after the two fixed octets, emitted
                verbatim ahead of ``payload``.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Note:
            **Keyword-only**, for two reasons.

            The four stay *declared*, unlike :meth:`read`'s own keywords,
            because :func:`~pcapkit.protocols.protocol._check_construction_keywords`
            builds its allowlist from :func:`inspect.signature` of ``make``.
            Hiding them in ``**kwargs`` **breaks construction**: a plain
            ``IPv6_Ext(next=..., len=..., data=..., payload=...)`` raises
            ``UnsupportedCall: IPv6_Ext: unexpected keyword(s)``. The
            ``__keywords__`` escape hatch would cover that, but it is unioned
            down the MRO, so it would widen the allowlist, and weaken that
            misspelling check, for all eight subclasses too.

            They are keyword-*only* because this class is also a base and each
            subclass's ``make`` puts different names in the same positions. As
            positional parameters they draw pylint ``arguments-renamed``
            warnings (``ESP.make`` has ``spi``, ``seq`` and ``next`` where
            these have ``next``, ``len`` and ``payload``) and mypy
            ``[override]`` errors. With no positional parameters there is no
            position to disagree about, and the allowlist is unaffected because
            ``_declared_keywords`` collects ``KEYWORD_ONLY`` parameters too.
            Nothing calls a protocol's ``make`` positionally; ``__init__``
            spreads ``**kwargs`` into it.

            ``read`` needs none of this: its ``alias``/``error`` only arrive on
            the *parse* path, which ``__init__`` exempts from the construction
            check.

        """
        # NOTE: The schema keeps everything after the two fixed octets as one
        # opaque payload, so the body is packed in front of the upper layer.
        if data:
            if isinstance(payload, ProtocolBase):
                payload = bytes(payload)
            elif isinstance(payload, Schema):
                payload = payload.pack()
            payload = data + payload

        return cast('_ST', Schema_IPv6_Ext(
            next=next,
            len=len,
            payload=payload,
        ))

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
            ProtocolError: If this is the *fallback* parser (see the class
                docstring's "two roles") and ``version`` is not ``6``.

        See Also:
            For construction argument, please refer to :meth:`make`.

        Note:
            The version gate is scoped to the fallback role by the same
            ``__data__`` discriminator :attr:`protocol` uses. Applying it to
            subclasses would break the two that are *not* IPv6-only:
            :class:`~pcapkit.protocols.internet.ah.AH` and
            :class:`~pcapkit.protocols.internet.esp.ESP` both default to
            ``version=4`` and are valid under IPv4, so an unconditional gate
            would reject them (``ProtocolError: ESP: only valid for IPv6, got
            version=4``).

            The gate exists because this class is registered into
            :attr:`Internet.__proto__
            <pcapkit.protocols.internet.internet.Internet.__proto__>`, which
            *every* :class:`~pcapkit.protocols.internet.internet.Internet`
            subclass shares, :class:`~pcapkit.protocols.internet.ipv4.IPv4`
            included, so that
            :attr:`~pcapkit.const.ipv6.extension_header.ExtensionHeader.Shim6`
            resolves to a working parser instead of
            :class:`~pcapkit.protocols.misc.raw.Raw`. Without it, an IPv4
            packet whose protocol byte is 140 would reach this class and walk
            an IPv6-style extension-header chain out of an IPv4 payload,
            reading ``IPv4:IPv6-Ext:...`` instead of the ``IPv4:Shim6`` that a
            plain, non-continuing ``Raw`` gives. Rejecting here sends
            construction back through
            :func:`~pcapkit.utilities.decorators.beholder` at the *caller's*
            layer, which substitutes that same ``Raw``: the version-agnostic
            behaviour, with no IPv4-specific code.

        """
        if self.__data__ is Data_IPv6_Ext and version != 6:
            raise ProtocolError(
                f'{self.__class__.__name__}: only valid for IPv6, got version={version}')

        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, version=version, extension=extension, **kwargs)  # type: ignore[arg-type]

    def __length_hint__(self) -> 'int':
        """Return an estimated length for the object.

        Eight octets, the shortest header :rfc:`6564#section-4` allows: Hdr
        Ext Len counts 8-octet units "not including the first 8 octets", and
        :rfc:`8200#section-4` makes every extension header a multiple of 8
        octets. Annotated ``int`` rather than ``Literal[8]``, for the reason
        given on :attr:`name`: every subclass has its own fixed header and its
        own ``Literal``.

        """
        return 8

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
                not per class: one :class:`IPv6_Ext` stands in for
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
    def _make_data(cls, data: 'Data_IPv6_Ext') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Emits the ``Hdr Ext Len`` octet and the body as they were read, so
        the rebuild is byte-exact whichever per-protocol length rule
        :meth:`read` applied, and also for an overrun, where ``data.next`` is
        :data:`None` and ``data.declared_next`` keeps the octet.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'next': data.declared_next,
            'len': data.len,
            'data': data.data,
            'payload': cls._make_payload(data),
        }


# NOTE: Registered by direct assignment into ``Internet.__proto__``, as
# ``pcapkit.protocols.internet.internet`` does for every other entry, rather
# than via the ``code=`` keyword of ``ProtocolBase.__init_subclass__``. The two
# are equivalent in effect, but ``code=`` resolves through
# ``register_protocol_code``, which imports
# ``pcapkit.foundation.registry.protocols`` *at class-definition time*, while
# ``pcapkit.protocols.internet`` (which imports this module) is still being
# built. From here that completes a cycle back into the unfinished
# ``pcapkit.protocols.internet`` through ``pcapkit.foundation.extraction``:
# ``ImportError: cannot import name 'Extractor' from partially initialized
# module 'pcapkit.foundation.extraction'`` on a bare ``import pcapkit``. Plain
# dict assignment carries no import of its own.
Internet.__proto__[Enum_TransType.Shim6] = IPv6_Ext
