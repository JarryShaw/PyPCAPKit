.. _utilities-or-corekit:

Choosing Between ``utilities`` and ``corekit``
----------------------------------------------

Which of the two support packages a module belongs in. Settled by the owner on
:issue:`1712`, over sorting modules by packet knowledge or by who uses them: this rule
can be checked from the import graph alone, and needed the fewest moves.

The page's questions, as one decision:

.. mermaid::

   flowchart TD
       NEW["a new support module,<br/>helper, constant<br/>or ContextVar"] --> CONST{"a constant?"}
       CONST -->|"referenced beyond its<br/>protocol or family"| SHARED["corekit.const<br/>one module per topic"]
       CONST -->|"referenced by its<br/>protocol or family alone"| OWNC["the const module of its<br/>package or family base"]
       CONST -->|no| LAYER{"a schema-layer<br/>helper used<br/>outside it?"}
       LAYER -->|no| OWNED{"a helper in<br/>one protocol's<br/>own modules?"}
       LAYER -->|yes| SCHEMA["corekit.schema<br/>one module per group"]
       OWNED -->|"in its schema, used<br/>beyond its protocol<br/>or family"| SCHEMA
       OWNED -->|"elsewhere, used<br/>beyond its protocol<br/>or family"| UTIL
       OWNED -->|no| VAR{"a ContextVar?"}
       OWNED -->|"used by its protocol<br/>or family alone"| STAY["stays in its<br/>protocol or family"]
       VAR -->|"set or read by<br/>several modules"| CTX["utilities.contextvars"]
       VAR -->|no| UTIL{"usable by any<br/>code, importing<br/>no pcapkit but<br/>utilities?"}
       VAR -->|"used by one<br/>module only"| PRIV["private, in<br/>that module"]
       UTIL -->|yes| VER{"differs by<br/>interpreter<br/>version?"}
       UTIL -->|no| CORE["corekit"]
       VER -->|yes| COMPAT["utilities.compat, behind<br/>a sys.version_info gate"]
       VER -->|no| OWN["a utilities module,<br/>not compat"]

:mod:`pcapkit.utilities` **is for cross-cutting services**: exceptions, warnings,
logging, the compatibility layer, configuration, and wrappers around third-party
libraries such as :mod:`~pcapkit.utilities.chardet`. Ask of a module: *could any code
use this service, and does it import nothing from* :mod:`pcapkit` *outside*
``utilities``? Both halves must hold, and *nothing* covers top-level, in-function and
``TYPE_CHECKING`` imports alike.
:file:`tests/project/test_utilities_import_boundary_1735_unit.py` checks every module
under :file:`pcapkit/utilities/`.

:mod:`pcapkit.utilities.compat` **holds compatibility implementations and re-exports
only.** Where a name or behaviour differs by interpreter version, ``compat`` re-exports
the right one behind a :data:`sys.version_info` gate rather than a ``getattr`` or
``hasattr`` probe. Ruled in review of the threading excepthook and ``AppType`` union
fixes for :issue:`1691` and :issue:`1694`, whose threads do not hold it, and applied to
the other probes on :issue:`1709`.
:file:`tests/project/test_stdlib_feature_probes_1709_unit.py` fails on a ``getattr``
or ``hasattr`` call naming its attribute in a string literal, where the receiver is a
builtin class or a module the file binds with an ``import`` statement, or where the
attribute is one the test lists with the interpreter version that added it, unless the
test exempts the call. A helper that must behave the same on every platform is neither
a compatibility implementation nor a re-export, so it gets its own module:
:func:`~pcapkit.utilities.datetime.fromtimestamp` is in
:mod:`pcapkit.utilities.datetime`, ruled in review of the timestamp fix for
:issue:`2099`, whose thread does not hold it.

:mod:`pcapkit.utilities` **stays flat**: a module there is named after the
standard-library module it extends, as :mod:`~pcapkit.utilities.inspect` and
:mod:`~pcapkit.utilities.datetime` are, or after its topic, as
:mod:`~pcapkit.utilities.config` is, and one holding a single function is fine. The
standard-library name tells a reader where to look; a ``helpers`` package nesting the
small modules would move their import paths without reducing their number; and
merging unrelated helpers into one module would break the one module per topic that
`Shared Helpers`_ asks for. Ruled by the owner in session and recorded on
:issue:`2908`.

:mod:`pcapkit.corekit` **is for the types the packet model is built from**: what
:mod:`pcapkit.protocols`, :mod:`pcapkit.const` and :mod:`pcapkit.foundation`
subclass, instantiate or decorate with. Ask: *is this part of what a protocol or its
schema is made of?* A support module that fails the ``utilities`` question belongs
here. :mod:`pcapkit.corekit.decorators` acts on a protocol's file and falls back to
protocol classes, so it moved out of ``utilities`` on :issue:`1735`. ``corekit`` may
import ``utilities``; the rule forbids the reverse.

:mod:`pcapkit.corekit.checksum`, settled on :issue:`2580`, fails the ``utilities``
question because :class:`~pcapkit.corekit.checksum.internet.ChecksumStatus` subclasses
:class:`~pcapkit.corekit.enum.EnumLookup`. The protocols compute and verify checksums
through it, so it imports :mod:`pcapkit` only from ``corekit`` and ``utilities``, never
from :mod:`pcapkit.protocols`, as
:file:`tests/corekit/test_checksum_import_boundary_2580_unit.py` checks. What needs IPv4
and IPv6 stays beside
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`. The package has
a module per checksum family, so a new family sits beside
:mod:`~pcapkit.corekit.checksum.internet`.

Shared Schema Helpers
~~~~~~~~~~~~~~~~~~~~~

**A helper that code outside the schema layer calls lives in**
:mod:`pcapkit.corekit.schema`, one module per group, rather than in the module that
first needed it; the schema layer is :mod:`pcapkit.corekit.fields` and
:mod:`pcapkit.protocols.schema`. It keeps no re-export at its old path. Ruled by the
owner in session on :issue:`2674`, grouping these helpers in one package rather than
placing each by the questions above. So
:func:`~pcapkit.corekit.schema.padding.pad_length` is in
:mod:`pcapkit.corekit.schema.padding`, and
:func:`~pcapkit.corekit.schema.shortread.keep_short_read` and
:func:`~pcapkit.corekit.schema.shortread.replay_short_read` in
:mod:`pcapkit.corekit.schema.shortread`. The header schema framework stays
:mod:`pcapkit.protocols.schema` and its :class:`~pcapkit.protocols.schema.Schema`;
:mod:`pcapkit.corekit.schema` holds only the helpers shared across the layer.

**A capture cut belongs to the built-in short read of**
:class:`~pcapkit.protocols.schema.Schema`. :meth:`Schema.unpack
<pcapkit.protocols.schema.Schema.unpack>` records the field the data ends
inside, through ``_note_short_read``, as ``__short_read__``;
:meth:`~pcapkit.protocols.schema.Schema._cut_short_read` packs back only the
octets read; and :func:`~pcapkit.corekit.schema.shortread.keep_short_read` and
:func:`~pcapkit.corekit.schema.shortread.replay_short_read` carry the record through
``info`` and cut a rebuild back by it. A protocol reads and rebuilds a cut header
through them, never through an ``unpack`` override of its own or a length callable
clamped to the octets present, which hides the cut from the record. Ruled in review
of :pr:`2682` (:issue:`2680`), and applied to option areas on :issue:`2694`.

**A rebuild is read at the width its parse read the header at.**
:func:`~pcapkit.corekit.schema.shortread.keep_short_read` records that width beside
the record, as ``__short_width__``, and :meth:`Protocol.from_data
<pcapkit.protocols.protocol.Protocol.from_data>` reads the rebuild at it, so it holds
the values and the next layer its parse did. Ruled by the owner on :issue:`2761`, over
a clamp inside :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext`, whose
overrunning ``length`` showed the gap.

A field callback tells a zero the cut left from a zero read through the same record:
:meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>` passes it to the fields
after the one the data ends inside, as ``__short_read__`` in their packet. A callback
that would refuse such a zero leaves it to the short read, and refuses a read value
with a :exc:`~pcapkit.utilities.exceptions.ProtocolError`, as the ``Opt Data Len``
helpers of :mod:`pcapkit.protocols.internet.ipv6_ext.schema` do (:issue:`2727`).

**On its own, the end of the data is a cut; inside a frame, the frame's lengths say
where the message ends.** A layer parsed with no layer before it, as
:data:`~pcapkit.utilities.contextvars.frame_depth` tells, is given the octets
captured, so :meth:`Protocol.unpack <pcapkit.protocols.protocol.Protocol.unpack>`
unpacks its header with ``__data_end__``. Past the cut, :meth:`Schema.unpack
<pcapkit.protocols.schema.Schema.unpack>` then warns nothing of ``__length__`` falling
below zero and resolves no length below zero from the zeros the cut left, so those
fields read nothing and the short read records the cut. Settled on :issue:`2880`,
completing :issue:`2848`. Inside a frame a field running past the length the enclosing
layer declares overruns it and warns, and the frame keeps a header its octets cannot
hold as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

A protocol's own check follows the same rule through
:func:`~pcapkit.corekit.schema.shortread.cut_on_its_own`. On its own, a version or
length the cut left as zero, or a header length the data ends before, is the short
read's, as such a zero is for a field callback (:issue:`2727`).
:func:`~pcapkit.corekit.schema.shortread.fill_short_options` rebuilds that header
length, which :issue:`1404` refused because the rebuild filled the zeros in. A check
the cut leaves nothing to decide by still refuses: the PCAP magic number, IGMP's
classification by length, NGAP's PER decoding, and the TLS, DTLS and HTTP/2 framing.

**A helper in one protocol's own schema module moves there too once code outside that
protocol or its family uses it**, so other implementors can find it; a helper only its
own protocol calls stays beside the schema. Ruled on :issue:`2674`, and widened to the
rest of a protocol's own modules on :issue:`2897` (`Shared Helpers`_). A protocol's
own modules are its protocol, data, schema and const modules. So
:func:`~pcapkit.corekit.schema.jumbogram.jumbo_payload_length`, which the IPv6
pseudo-header and the Scapy toolkit read as well as IPv6 itself, is in
:mod:`pcapkit.corekit.schema.jumbogram`, while
:func:`~pcapkit.protocols.internet.ipv6.schema.jumbogram_error`, which only IPv6
calls, stays in :mod:`pcapkit.protocols.internet.ipv6.schema`. The IPv6 option
helpers in :mod:`pcapkit.protocols.internet.ipv6_ext.schema` belong to the HOPOPT
and IPv6-Opts headers that share them, and stay there too.

**A header's length converts to and from a field counting 8-octet units not
including the first 8 octets** [:rfc:`6564#section-4`] through
:mod:`pcapkit.corekit.schema.extlen`, MH's and HIP's included (:issue:`2854`).
AH counts 4-octet units with a bias of 2 [:rfc:`4302#section-2.2`], so it keeps
its own arithmetic. :file:`tests/project/test_ext_len_arithmetic_2854_unit.py`
fails on ``(field + 1) * 8``, split across a call or not, or its inverse written
out anywhere else in :mod:`pcapkit`.

The field modules and the protocols import these helpers, so a helper module imports
neither, nor :mod:`pcapkit.foundation`, outside an ``if TYPE_CHECKING:`` block. The
package's ``__init__.py`` imports none of its modules, so a field module loads only the
group it asks for.
:file:`tests/project/test_schema_helpers_boundary_2674_unit.py` fails on a helper
module that does, on a module outside the layer that refers to a function defined in
a field module or in :mod:`pcapkit.protocols.schema`, and on a module outside
a protocol that refers to a function defined in that protocol's schema module, by
import or as an attribute of the module.

Shared Constants
~~~~~~~~~~~~~~~~

**A constant the format or the RFCs fix that anything outside its own protocol
references lives in** :mod:`pcapkit.corekit.const`, in the module for its topic, not
in the protocol that first needed it. Ruled by the owner on :issue:`2883`, over a
constants module beside each protocol's schema, which adds a fourth module kind and
keeps the cross-layer imports. The package of topic modules, beside
:mod:`pcapkit.corekit.schema` since most of its readers are not schema code, was
ruled in review of :pr:`2895` (:issue:`2883`), over topic modules among the schema
helpers and over one module holding every topic. :mod:`pcapkit.const` is no home,
since :ref:`const-vendor-pairing` gives each of its modules a crawler; it holds the
enumerations generated from the vendor registries.

*  :mod:`pcapkit.corekit.const.capture` -- the PCAP and PCAP-NG values the
   engines, the dumpers and the toolkit read: magic numbers, timestamp
   resolutions, the record header length, the Byte-Order Magic and the block
   minimums.
*  :mod:`pcapkit.corekit.const.ipheader` -- the IPv4, IPv6 and IP
   Authentication Header lengths and offsets, and
   :data:`~pcapkit.corekit.const.ipheader.IP_MAX_LENGTH`.
*  :mod:`pcapkit.corekit.const.tcpheader` -- the TCP header's minimum length
   and the octet holding its Data Offset.

What counts as a reference was ruled in review of :pr:`2895` (:issue:`2883`) too. Any
module counts -- another protocol, the engines, the dumpers, IP reassembly and the
toolkit alike -- but a protocol's own ``protocol``, ``schema``, ``data`` and
``const`` modules are one place, and so is a family. So a family base's constant
that its members reference stays with the family, as the IPv6 option helpers do
(:issue:`2674`): TLS and DTLS read SSL's record content types, and HTTP/1 and
HTTP/2 the HTTP base's patterns.

Every layer imports these modules, so they import nothing from :mod:`pcapkit` but
:mod:`pcapkit.const` outside an ``if TYPE_CHECKING:`` block, and the package's
``__init__.py`` imports none of them.
:file:`tests/project/test_shared_format_constants_2883_unit.py` fails on a module
there that does, and on a constant of a protocol's own modules that a module outside
that protocol or its family references, by import or as an attribute of the module.

**Every other constant of a protocol's own modules lives in its package's**
``const`` **module**, whichever of its ``protocol``, ``schema`` and ``data`` modules
reads it, and one a family shares in the family base's: SSL's for TLS and DTLS,
HTTP's for HTTP/1 and HTTP/2. Ruled by the owner in review of :pr:`2895`
(:issue:`2883`) and recorded on :issue:`2896`. So
:data:`~pcapkit.protocols.misc.pcap.header.const.GLOBAL_HEADER_LEN`, which only the
PCAP global header reads, is in :mod:`pcapkit.protocols.misc.pcap.header.const`.

A constant is a module-level name in capitals, such as ``LIMIT``, ``_LIMIT`` or each
name of a tuple bound at once, whose value is fixed when its module loads: a
number, a string, a compiled pattern, an enumeration member, or a table of them.
These are not constants, and stay beside their readers:

*  a :class:`~pcapkit.corekit.module.ModuleDescriptor`, a lazy import;
*  run-time state: a name a function rebinds under ``global``, as
   :data:`~pcapkit.protocols.internet.esp.protocol._CRYPTO` is, or a lock;
*  a value built from :mod:`pcapkit` beyond the registries and the constants -- a
   field, a schema or a class of its own module -- as
   :data:`~pcapkit.protocols.internet.esp.protocol.CIPHER_SUITES` is, which a
   ``const`` module could not import without importing its protocol back.

The modules that read a constant import it, so it stays reachable through them and
needs no ``versionremoved`` (:issue:`2896`); a released path whose module no longer
reads it records one, as ``pcapkit.protocols.application.ssl.protocol.TLS13_VERSION``
does. Those modules import a ``const`` module, so it imports nothing from
:mod:`pcapkit` but :mod:`pcapkit.const`, :mod:`pcapkit.corekit.const` and another
``const`` module outside an ``if TYPE_CHECKING:`` block, defines no function or
class, and its ``__all__`` lists its public constants. The same test fails on a
constant a ``protocol``, ``schema`` or ``data`` module binds, and on a ``const``
module that binds anything else or imports beyond these.

Shared Helpers
~~~~~~~~~~~~~~

**A function or class of a protocol's own modules that anything outside its protocol
or family references lives in a common home**: the module of :mod:`pcapkit.utilities`
or :mod:`pcapkit.corekit` for its topic, as the questions above place it, and never a
generic helpers module. Ruled by the owner in review of :pr:`2895` (:issue:`2883`)
and recorded on :issue:`2897`. References and places count as for the constants, and
so does a :class:`~pcapkit.corekit.module.ModuleDescriptor` naming the helper, as a
lazy import does. So :func:`~pcapkit.corekit.schema.byteorder.family_byteorder`,
which the `DPKT`_ engine reads as well as
:class:`~pcapkit.protocols.link.loopback.protocol.Loopback`, is among the byte-order
helpers of :mod:`pcapkit.corekit.schema.byteorder`: it reads
:class:`~pcapkit.const.reg.linktype.LinkType`, so fails the ``utilities`` question.
The next-layer and link-address checks that
:class:`~pcapkit.protocols.link.linux_sll1.protocol.LinuxSLL1` and
:class:`~pcapkit.protocols.link.linux_sll2.protocol.LinuxSLL2` share stay in their
family base's :mod:`pcapkit.protocols.link.linux_sll.protocol`.

**A protocol's own structures are not helpers**: the dissector, header schema and data
model classes its modules hold (:ref:`protocol-family-grouping`), every subclass of
:class:`~pcapkit.protocols.protocol.ProtocolBase`,
:class:`~pcapkit.protocols.schema.Schema` or :class:`~pcapkit.corekit.infoclass.Info`
there, stay in its package whoever references them, as the framework bases do. A field
class, an enumeration or a context its modules define is a helper.

**The IP pseudo-header's functions stay beside it.**
:func:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.pseudo_header`,
:func:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.compute_upper` and
:func:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.verify_upper`, which the IP
layers and the layers above them reach through a
:class:`~pcapkit.corekit.module.ModuleDescriptor`, act on
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo` and through it
on IPv4 and IPv6, which is what :issue:`2580` keeps in
:mod:`pcapkit.protocols.misc.checksum`.

:file:`tests/project/test_shared_format_constants_2883_unit.py` fails on a helper a
module outside its protocol or family references, the pseudo-header functions aside,
and imports a class to tell a structure from a helper.

Context Variables
~~~~~~~~~~~~~~~~~

Where a :class:`~contextvars.ContextVar` lives depends on which modules use it.
Settled by the owner on :issue:`2616`:

*  **One that more than one module sets or reads lives in**
   :mod:`pcapkit.utilities.contextvars`, under a public name in its ``__all__``. No
   other module re-exports it, so every reader imports it from there.
*  **One that only its own module uses stays in that module**, private, as
   ``_exthdr_rebuilt`` does in :mod:`pcapkit.protocols.internet.internet`.

A shared variable kept in one of its users makes the others import a private name
and ties them to that module's place in the import graph. A module of bare
declarations importing nothing from :mod:`pcapkit` passes the ``utilities`` question,
so any module may import it -- :mod:`pcapkit.corekit.checksum` included, which must not
reach :mod:`pcapkit.protocols`. :file:`tests/project/test_shared_contextvars_2616_unit.py`
fails on a module that takes a context variable from anywhere else, by name or as an
attribute of an imported module, and on a variable there that is private, missing
from ``__all__``, or read by one module alone.
