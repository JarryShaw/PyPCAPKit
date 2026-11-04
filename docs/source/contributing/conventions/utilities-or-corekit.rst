.. _utilities-or-corekit:

Choosing Between ``utilities`` and ``corekit``
----------------------------------------------

Which of the two support packages a module belongs in. Settled by the owner on
:issue:`1712`, over alternatives that sorted modules by packet knowledge or by
who uses them. This rule can be checked from the import graph alone, and it needed
the fewest moves: one.

:mod:`pcapkit.utilities` **is for cross-cutting services**: exceptions, warnings,
logging, the compatibility layer, configuration, and wrappers around third-party
libraries such as :mod:`~pcapkit.utilities.chardet`. The question to ask of a module
is *could any code use this service, and does it import nothing from* :mod:`pcapkit`
*outside* ``utilities``? Both halves have to hold, and *nothing* covers a top-level
import, one inside a function and one under ``TYPE_CHECKING`` alike.
:file:`tests/project/test_utilities_import_boundary_1735_unit.py` checks every module
under :file:`pcapkit/utilities/` for it.

:mod:`pcapkit.utilities.compat` **holds compatibility implementations and re-exports
only.** Where a name or behaviour differs by interpreter version, ``compat`` re-exports
the right one behind a :data:`sys.version_info` gate rather than a ``getattr`` or
``hasattr`` probe. That was ruled in review of the threading excepthook and
``AppType`` union fixes for :issue:`1691` and :issue:`1694`, neither of whose threads
holds it, and applied to the package's other probes on :issue:`1709`.
:file:`tests/project/test_stdlib_feature_probes_1709_unit.py` fails on a ``getattr``
or ``hasattr`` call naming its attribute in a string literal, where the receiver is a
builtin class or a module the file binds with an ``import`` statement, or where the
attribute is one the test lists with the interpreter version that added it; the calls
it exempts pass. A helper that has to behave the same on every platform is
neither a compatibility implementation nor a re-export, so it gets a module of its
own: that is why :func:`~pcapkit.utilities.datetime.fromtimestamp` is in
:mod:`pcapkit.utilities.datetime`, ruled in review of the timestamp fix for
:issue:`2099`, whose thread does not hold it.

:mod:`pcapkit.corekit` **is for the types the packet model is built from**: what
:mod:`pcapkit.protocols`, :mod:`pcapkit.const` and :mod:`pcapkit.foundation`
subclass, instantiate or decorate with. The question is *is this part of what a
protocol or its schema is made of?* A support module that fails the ``utilities``
question belongs here instead. :mod:`pcapkit.corekit.decorators` is the worked example: it acts on a
protocol's file and falls back to protocol classes, so it moved out of ``utilities``
on :issue:`1735`. ``corekit`` may import ``utilities``; the reverse is what the rule
forbids.

A second worked example is :mod:`pcapkit.corekit.checksum`, settled on :issue:`2580`.
It fails the ``utilities`` question because
:class:`~pcapkit.corekit.checksum.internet.ChecksumStatus` subclasses
:class:`~pcapkit.corekit.enum.EnumLookup`. The protocols compute and verify their
checksums through it, so it imports
:mod:`pcapkit` only from ``corekit`` and ``utilities``, never from
:mod:`pcapkit.protocols`; :file:`tests/corekit/test_checksum_import_boundary_2580_unit.py`
checks that. What needs IPv4 and IPv6 stays beside
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`. The package holds one
module per checksum family, so a new family sits beside
:mod:`~pcapkit.corekit.checksum.internet`.

Shared Schema Helpers
~~~~~~~~~~~~~~~~~~~~~

**A helper that code outside the schema layer calls lives in**
:mod:`pcapkit.corekit.schema`, one module per group, rather than in the module that
first needed it; the schema layer is :mod:`pcapkit.corekit.fields` and
:mod:`pcapkit.protocols.schema`. It keeps no re-export at its old path. Ruled by the
owner in session, on :issue:`2674`, who grouped these helpers in one package instead
of placing each by the questions above. So
:func:`~pcapkit.corekit.schema.padding.pad_length` is in
:mod:`pcapkit.corekit.schema.padding`, and
:func:`~pcapkit.corekit.schema.shortread.keep_short_read` and
:func:`~pcapkit.corekit.schema.shortread.replay_short_read` in
:mod:`pcapkit.corekit.schema.shortread`. :mod:`pcapkit.corekit.schema` is not the
header schema framework, which stays :mod:`pcapkit.protocols.schema` and its
:class:`~pcapkit.protocols.schema.Schema`; it holds only the helpers shared
across the layer.

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
a clamp inside :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext`, the one
protocol whose overrunning ``length`` showed the gap.

A field callback tells a value the cut left as zero from one read through the same
record: :meth:`Schema.unpack <pcapkit.protocols.schema.Schema.unpack>` gives
it to the fields after the one the data ends inside, as ``__short_read__`` in their
packet. A callback that would refuse such a zero leaves it to the short read, and
refuses a value read with a :exc:`~pcapkit.utilities.exceptions.ProtocolError`, as
the ``Opt Data Len`` helpers of
:mod:`pcapkit.protocols.internet.ipv6_ext.schema` do (:issue:`2727`).

**A helper in one protocol's own schema module moves there too once code outside that
protocol uses it and it is generic enough to reuse**, so that another implementor can
find it; a helper only its own protocol calls stays beside the schema. Ruled on
:issue:`2674`. A protocol's own modules are its protocol, data and schema modules. So
:func:`~pcapkit.corekit.schema.jumbogram.jumbo_payload_length`, which the IPv6
pseudo-header and the Scapy toolkit read as well as IPv6 itself, is in
:mod:`pcapkit.corekit.schema.jumbogram`, while
:func:`~pcapkit.protocols.internet.ipv6.schema.jumbogram_error`, which only IPv6
calls, stays in :mod:`pcapkit.protocols.internet.ipv6.schema`. The IPv6 option
helpers in :mod:`pcapkit.protocols.internet.ipv6_ext.schema` belong to the HOPOPT
and IPv6-Opts headers that share them, and stay there too.

The field modules and the protocols import these helpers, so a helper module imports
neither of them, nor :mod:`pcapkit.foundation`, outside an ``if TYPE_CHECKING:``
block; the package's ``__init__.py`` imports none of its modules, so a field module
loads only the group it asks for.
:file:`tests/project/test_schema_helpers_boundary_2674_unit.py` fails on a helper
module that does, on a module outside the layer that refers to a function defined in
a field module or in :mod:`pcapkit.protocols.schema`, and on a module outside
a protocol that refers to a function defined in that protocol's schema module, by
import or as an attribute of the module.

Context Variables
~~~~~~~~~~~~~~~~~

Where a :class:`~contextvars.ContextVar` lives depends on which modules use it.
Settled by the owner on :issue:`2616`:

*  **One that more than one module sets or reads lives in**
   :mod:`pcapkit.utilities.contextvars`, under a public name in its ``__all__``. No
   other module re-exports it, so every reader imports it from there.
*  **One that only its own module uses stays in that module**, private, as
   ``_exthdr_rebuilt`` does in :mod:`pcapkit.protocols.internet.internet`.

A shared variable kept in one of the modules that use it makes the others import a
private name from that module, and ties them to its place in the import graph. A
module of bare declarations that imports nothing from :mod:`pcapkit` passes the
``utilities`` question above, so any module may import it --
:mod:`pcapkit.corekit.checksum` included, which must not reach
:mod:`pcapkit.protocols`. :file:`tests/project/test_shared_contextvars_2616_unit.py`
fails on a module that takes a context variable from anywhere else, by name or as an
attribute of an imported module, and on a variable there that is private, missing
from ``__all__``, or read by one module alone.
