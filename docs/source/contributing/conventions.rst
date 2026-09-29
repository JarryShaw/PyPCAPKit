House Conventions
=================

.. important::

   This page records **design rulings** for :mod:`pcapkit` -- decisions that
   are not derivable from the code, and that a future maintainer or an automated
   contributor would otherwise have to rediscover by reading a closed issue
   thread. Each ruling names where it was settled.

   Most of them govern :mod:`pcapkit.const`, which is where the settled questions
   have mostly arisen, and the page was titled *Registry Conventions* for that
   reason until `#918 <https://github.com/JarryShaw/PyPCAPKit/issues/918>`__
   widened it. :ref:`extension-header-subclassing` is the first ruling here that
   governs a protocol class hierarchy rather than a registry.

   **A ruling that stays in its thread is a ruling that gets rediscovered.** So
   when a question is answered in a way the code cannot express on its own -- a
   classification, a naming rule, a deliberate asymmetry -- it is written onto
   this page in the same change that implements it, rather than being left in the
   issue for the next contributor to find. The owner's standing ask, on
   `#918 <https://github.com/JarryShaw/PyPCAPKit/issues/918>`__: *"And any future
   conventions to be settled - document them as well."*

.. _mint-criterion:

When an unrecognised value may mint a member
--------------------------------------------

Every registry under :mod:`pcapkit.const` defines ``_missing_``, which decides what
happens when a value has no member. There are two possible behaviours, and which one
a given range gets is a **design decision, not a style preference**:

``extend_enum(cls, name, value)`` -- *mint*
   Creates a real, permanent member on the class. It is installed in
   ``_member_map_`` and ``_value2member_map_``, so it is visible to iteration,
   lookup and ``__members__`` from then on, for the life of the process.

:meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member` -- *unmint*
   Returns a member-like object for the value **without** installing it. The
   registry does not grow, and a second lookup of the same value is indistinguishable
   from the first.

The criterion
~~~~~~~~~~~~~

The test, in the maintainer's words:

   Is this considered as the final concrete assigned name (**mint**), or just a
   notation for the readers (**unmint**)?

Settled on `#847 <https://github.com/JarryShaw/PyPCAPKit/issues/847>`__ and confirmed
as "a core concept of the ruling" on
`#775 <https://github.com/JarryShaw/PyPCAPKit/issues/775>`__.

So the question to ask of a range is **what the upstream registry actually did**, not
what the generated code happens to look like:

*  The source assigns a **real, specific name** to those codes -- minting records
   something the registry genuinely says. **Mint.**
*  The source says only that the codes are spoken for, without naming them --
   ``Unassigned``, ``Reserved``, ``Reserved for Private Use``,
   ``Reserved for Experimental Use``, ``Deprecated``, ``Dynamically Assigned``
   and ``Statically Assigned``. These are written for a human reading the
   table. Minting them **manufactures a name nobody
   assigned**, and the value will get its real name if and when something assigns
   it. **Unmint.**

Worked examples
~~~~~~~~~~~~~~~

*Unmint.* :mod:`pcapkit.const.ipx.socket`'s ``Dynamically Assigned``,
``Dynamically Assigned Socket Numbers``, ``Statically Assigned Socket Numbers`` and
``Experimental`` ranges. Each names **how the socket will be allocated**, not what
occupies it; the real name arrives with the allocation.

*Mint.* :mod:`pcapkit.const.reg.ethertype`'s company names -- ``Xyplex``,
``Datability``, ``Qualcomm``, ``Motorola`` and forty-two others, 46 names across 50
range blocks, since four of them hold two blocks each -- and, in the same file's
neighbour, :mod:`pcapkit.const.ipx.socket`'s ``Registered by Xerox``. A company name
is the assignment, for the reason in the next section.

Two further ranges in that file mint without being company names at all:
``IEEE802.3 Length Field``, which names a field in a standard, and
``Berkeley Trailer encap/IP``, which names an encapsulation. Both are outside the 46,
and neither mints for the reason the next section gives.

.. note::

   Those two groups look alike and the line between them is **not** range-versus-single
   code. ``Registered by Xerox`` covers a range and still mints, because it names *who
   registered the socket*. ``Dynamically Assigned`` also covers a range and does not,
   because it names only the *mechanism* by which some future party will take it. Ask
   what the label tells you: a party, or a procedure.

Why the company names mint
~~~~~~~~~~~~~~~~~~~~~~~~~~

The ethertype case looks like an exception to the rule and is not. The maintainer's
reasoning, settled on `#775 <https://github.com/JarryShaw/PyPCAPKit/issues/775>`__ after
being raised on `#847 <https://github.com/JarryShaw/PyPCAPKit/issues/847>`__:

   Proprietary protocols won't have public names so company names serve this purpose.

So the company name is not a note *about* the code -- it is the best name that will ever
exist *for* it, which makes it the final concrete assigned name under the test above.
That is also why ``DEC Unassigned`` goes the other way despite carrying the same
attribution: there the company holds the block and assigned nothing, so the notation is
"Unassigned" and the attribution is incidental.

Checking the current state
~~~~~~~~~~~~~~~~~~~~~~~~~~

The split is measurable rather than a matter of memory. Slice each ``_missing_`` body
and see which call it makes -- an :mod:`ast` walk is reliable where a text search is
not, because ``extend_enum`` also appears in imports and in prose:

.. code-block:: python

   import ast, pathlib

   for path in sorted(pathlib.Path('pcapkit/const').rglob('*.py')):
       if path.name == '__init__.py':
           continue
       tree = ast.parse(path.read_text())
       for node in ast.walk(tree):
           if isinstance(node, ast.FunctionDef) and node.name == '_missing_':
               calls = {n.func.id for n in ast.walk(node)
                        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
               if 'extend_enum' in calls:
                   print('MINT  ', path)
               elif '_unregistered_member' in calls:
                   print('UNMINT', path)

.. warning::

   Calling ``Cls(value)`` on a registry whose ``_missing_`` mints **mutates the
   class**. A probe is not a read: it installs a member that every later lookup then
   finds. Snapshot ``{member.value for member in Cls}`` before any lookup, and use a
   throwaway process per registry when comparing behaviour across revisions.

.. _sentinel-convention:

Naming a sentinel
-----------------

A *sentinel* here is a module-level singleton whose only job is to be recognised by
identity -- ``value is SENTINEL`` -- so that it can never be confused with a value a
caller might legitimately pass. The house rule, from the maintainer:

   Keep the sentinel object's type class naming as ``<SENTINEL>Type``.

That is, the class takes the instance's name in CamelCase with ``Type`` appended. The
four in the tree follow it:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Instance
     - Type
     - Defined in
   * - ``NULL``
     - ``NullType``
     - :mod:`pcapkit.corekit.sentinels`
   * - ``NoValue``
     - ``NoValueType``
     - :mod:`pcapkit.corekit.sentinels`
   * - ``NO_DEFAULT``
     - ``NoDefaultType``
     - :mod:`pcapkit.corekit.sentinels`
   * - ``_Absent``
     - ``_AbsentType``
     - :mod:`pcapkit.corekit.sentinels`

All four used to live beside the one class that used them --
:mod:`pcapkit.corekit.module`, :mod:`pcapkit.corekit.fields.field`,
:mod:`pcapkit.corekit.enum` and :mod:`pcapkit.protocols.protocol` respectively.
GitHub issue #911's housing ruling, verbatim -- *"Okay one module for all four it
is."* -- moved the four definitions into the single shared module the table now
names; each original module keeps a re-export so every existing
``from <module> import <name>`` keeps working, including the
``if TYPE_CHECKING:``-only imports of the types.

Note what the rule does **not** fix: the **instance** name's casing is deliberately
free, which is why ``NULL`` and ``NoValue`` disagree and both are correct. Pick
whichever reads better at the call site, and where a name already exists, keep it --
renaming a published sentinel costs every caller for no gain.

Nor does it fix the **leading underscore**. ``_Absent`` is private -- it is read in
``_declared_keywords`` and discarded there, never leaving
:mod:`pcapkit.protocols.protocol` even though its *definition* now does -- and it is
still held to the convention, which is why its type is ``_AbsentType`` and not
``_Absent_t`` or ``Absent``. It is a deliberate fourth rather than an accident, and
its own docstring (:file:`pcapkit/corekit/sentinels.py`, line 430) says so:

   A distinct class rather than a bare :obj:`object` so that the sentinel has a name
   of its own in a traceback or a debugger, and so that a type checker has something
   to name where ``object()`` would give it nothing. It follows
   :class:`NoValueType`, which does the same job for an unset field default;
   this is a sibling of it rather than a reuse [...]

The private name is also why this table listed three for as long as it did: a sweep
filtered on capitalised names does not see it. When adding a sentinel, add it here
whether or not it is public.

What reaches users is the **object only**. The maintainer's ruling: *"we should ONLY
export the objects (like* ``NULL`` *) to users"* -- so a public sentinel names its
instance in its module's ``__all__`` and leaves the type out of it (GitHub issue #911).
The type stays importable by its dotted path, for an annotation or an ``is`` guard; it
is ``import *`` that no longer offers it. A private sentinel such as ``_Absent`` is in
neither, which is what private means here.

.. note::

   Of the four, only :class:`~pcapkit.corekit.sentinels.NullType` is a full worked
   example. ``NoValueType`` follows the naming rule but is **not** a singleton
   (``NoValueType() is NoValue`` is :obj:`False`) and has no ``__repr__`` of its own,
   so it demonstrates the name and nothing else; ``_AbsentType`` has a ``__repr__``
   (``<absent>``) but no singleton guard either. Copy ``NullType`` when you need a
   pattern to follow.

Why a class and not ``object()``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A bare ``object()`` is just as safe under ``is``, so safety is not the reason. The
reason is legibility: a dedicated class can define ``__repr__``, and that repr is what
appears in a signature, in :func:`help` output and in a traceback. Compare what
:func:`inspect.signature` renders for a method whose default is the sentinel:

.. code-block:: text

   # bare object(): an address, different every process
   default: 'Any' = <object object at 0x7fc393324cf0>

   # dedicated type with __repr__
   default: 'Any' = <NO_DEFAULT>

.. warning::

   Do **not** justify a dedicated class by claiming a subclass "could still compare
   equal via a custom ``__eq__``". A class that defines only ``__repr__`` inherits
   identity ``__eq__`` and is exactly as safe as ``object()``. That argument appeared
   in an early draft of :mod:`pcapkit.corekit.enum` and was wrong.

**Ported code is exempt.** ``_NOT_FOUND = object()`` at
:file:`pcapkit/utilities/compat.py`, line 73, sits inside the ``cached_property``
backport taken for interpreters below 3.8, which tracks CPython's own
:mod:`functools` implementation down to that name. It is **not** to be converted: the
value of a vendored backport is that it can still be diffed against upstream, and a
house-style rewrite destroys that in exchange for a sentinel nobody outside those forty
lines ever sees. The rule above is for sentinels this package writes itself.

What to implement, and what not to
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The four sentinels deliberately differ, and the differences are **needs, not
inconsistencies**:

``__new__`` returning a cached instance
   Guards against a caller constructing a second, non-identical sentinel that then
   fails every ``is`` check. Worth having wherever the type is reachable by a caller at
   all -- which, since the type is kept out of ``__all__``, means wherever it is
   importable by its dotted path rather than wherever it is star-exported.
   :class:`~pcapkit.corekit.sentinels.NullType` documents the limit honestly: a module
   **reload** re-executes the class statement, so the guard does not survive one, and
   code holding the pre-reload instance will fail ``is``. Since GitHub issue #911,
   that means reloading :mod:`pcapkit.corekit.sentinels` itself -- reloading
   :mod:`pcapkit.corekit.module`, which now only re-exports the sentinel, no longer
   has any effect on it.

``__bool__`` returning :obj:`False`
   ``NULL``, ``NoValue`` and ``_Absent`` have it, because each stands for an *absent
   value* and reads naturally in a boolean test. ``NO_DEFAULT`` deliberately does
   **not**: it is a marker meaning *no default was supplied*, it is only ever tested
   with ``is``, and making it falsy would invite ``if not default:`` -- which would
   then treat a caller's genuine falsy default (``0``, ``''``, :obj:`None`,
   :obj:`False`) the same as the sentinel, the very confusion the sentinel exists to
   prevent.

``__copy__`` / ``__deepcopy__`` / ``__reduce__``
   :class:`~pcapkit.corekit.sentinels.NullType` has them because ``NULL`` is stored in a
   :class:`~pcapkit.corekit.module.ModuleDescriptor` field, so a caller's
   :func:`copy.deepcopy` or :mod:`pickle` can walk into it and would otherwise
   reconstruct a second instance. ``NO_DEFAULT`` and ``_Absent`` have none, because
   neither is ever stored in any structure a caller copies -- one only ever appears as
   a default argument, and the other never leaves the module that reads it.
   Add them when, and only when, the sentinel becomes reachable from something
   copyable.

.. _registry-protocol:

Where the registry protocol lives
---------------------------------

:meth:`~pcapkit.corekit.enum.EnumLookup.get`,
:meth:`~pcapkit.corekit.enum.EnumLookup.get_all`,
:meth:`~pcapkit.corekit.enum.EnumRegistry.register` and
:meth:`~pcapkit.corekit.enum.EnumRegistry.register_alias` are expected to exist on
**every** registry, per the ruling on
`#842 <https://github.com/JarryShaw/PyPCAPKit/issues/842>`__. They come from
:class:`~pcapkit.corekit.enum.EnumRegistry`, mixed in ahead of the enum base so that
``_member_type_`` still resolves to :class:`int` or :class:`str`:

.. code-block:: python

   class LinkType(EnumRegistry, IntEnum):
       ...

A handful of registries define their own ``__new__`` to carry extra attributes and so
do not share the generated template; bringing them onto the base is tracked in
`#860 <https://github.com/JarryShaw/PyPCAPKit/issues/860>`__.

The Two Tiers, and What Lives on Each
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:class:`~pcapkit.corekit.enum.EnumRegistry` is not the only base any more. Since
phase 1 of `#877 <https://github.com/JarryShaw/PyPCAPKit/issues/877>`__ it has a
parent, and the line between them is whether the enumeration may *grow*:

=================================================== ==============================================================
:class:`~pcapkit.corekit.enum.EnumLookup`           ``get``, ``get_all``, ``_validate_value``
:class:`~pcapkit.corekit.enum.EnumRegistry`         ``register``, ``register_alias``, ``register_aliases``,
                                                    ``_extend``, ``_unregistered_member``
=================================================== ==============================================================

The owner's ruling, verbatim: *"they may subclass a bare base enum from
pcapkit.corekit.enum - where EnumRegistry subclasses it for using in the other
mutable ones."* So a **closed** set inherits :class:`~pcapkit.corekit.enum.EnumLookup`
directly and is never handed a ``register`` it would have to refuse; an **open**
registry inherits :class:`~pcapkit.corekit.enum.EnumRegistry` exactly as before.

What settled the split is the owner's own second thought about carrying ``register``
on the base: *"if it carries ``register``, then why not ``register_alias``. We might
be creating a bad ruling."* Following that through leaves
:class:`~pcapkit.corekit.enum.EnumRegistry` holding only three methods, too thin to
justify a second class -- so the two tiers collapse into one, which is the opposite of
what was ruled.

**Both tiers are plain classes, and that is load-bearing.** Inserting a parent above
:class:`~pcapkit.corekit.enum.EnumRegistry` leaves the member data type exactly where
it was -- ``LinkType -> EnumRegistry -> EnumLookup -> IntEnum -> int`` -- so
``_member_type_`` still comes from the enum base. Had either tier subclassed
:class:`~aenum.Enum` in order to "be an enum", it would have become the member type
itself and broken ``int``, ``str`` and flag registries at once.

:meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` is what the base carries
*instead* of ``register``, and it answers the owner's other requirement: *"there must
be some sort of range validation logic for the inherited classes to hook in."* The
base implementation accepts everything; an override states a range, in the shape the
generated registries currently spell by hand in ``_missing_``:

.. code-block:: python

   @classmethod
   def _validate_value(cls, value: 'Any') -> 'None':
       if not (isinstance(value, int) and 0 <= value <= 0xFF):
           raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')

Three things about it are easy to get wrong:

* **It guards, it does not convert.** The return type is :obj:`None` deliberately, so
  that an override cannot normalise a value on its way through and silently change
  what a lookup resolves to.
* **Raise from** :mod:`pcapkit.utilities.exceptions`.
  :exc:`~pcapkit.utilities.exceptions.EnumValueError` is the fitting one, and because
  it subclasses :exc:`ValueError` a rejection is caught by ``get``'s own ``except`` and
  falls back to ``default`` like any other unresolvable value. An override raising
  outside that hierarchy propagates past ``default`` instead.

  With **no usable** ``default``, the rejection reaches the caller **unwrapped**.
  ``get`` re-raises a :exc:`ValueError` that is already a
  :exc:`~pcapkit.utilities.exceptions.BaseError` exactly as the override raised it,
  and converts only :mod:`aenum`'s and :mod:`enum`'s own "no member carries this
  value". Two things follow, and both are the point of the discrimination rather
  than side effects: the override's **own message** survives to the caller instead
  of being replaced by the base's, and the error is **logged once** rather than
  twice, since :class:`~pcapkit.utilities.exceptions.BaseError` logs on
  construction and re-wrapping would construct a second one. So an override should
  say in its message what it rejected and why; that message is what the caller
  sees.
* **A** ``str`` **key never reaches it.** That path never calls ``cls(key)``, so it
  resolves only against already-populated lookup tables, where every value present is
  legal by construction. ``register`` does call it, after its duplicate check.

.. note::

   Re-parenting the remaining helper enumerations onto
   :class:`~pcapkit.corekit.enum.EnumLookup` is **phase 2** of
   `#877 <https://github.com/JarryShaw/PyPCAPKit/issues/877>`__, and it is **partly
   done** rather than pending: the phase landed for 17 of the 24 non-registry
   enumerations. **Seven are still outside the hierarchy**, measured by a runtime
   walk over both the :mod:`enum` and :mod:`aenum` flavours: ``CommandType`` and
   ``ConformanceRequirement`` in :mod:`pcapkit.const.ftp.command`, ``ESPStatus`` in
   :mod:`pcapkit.protocols.internet.esp`, and all four
   :mod:`pcapkit.protocols.internet.mh` helpers
   (``FastBindingAcknowledgmentStatus``, ``IPv6AddressPrefixCode``,
   ``LMAAddressCode``, ``LocalizedRoutingStatus``). Each sat in a file another pull
   request held open while phase 2 ran, which is the whole reason the phase was split
   in two: phase 1 is behaviour-preserving on its own, so it could land while work
   was still in flight on the files a re-parent touches. Do not read the seven as a
   ruling against re-parenting them -- they are the remainder of a phase, not an
   exception to it.

What a Failed Lookup Raises
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two rules govern it, and they pull in opposite directions on purpose. The owner's
ruling, verbatim, on
`#923 <https://github.com/JarryShaw/PyPCAPKit/issues/923>`__:

   Either ``ValueError`` or ``KeyError``, that's depending on how stdlib's ``Enum``
   would raise on these circumstances. And we should raise one from
   ``pcapkit.utilities.exceptions`` rather builtin exceptions.

So the **provenance** is in-library and the **shape** is stdlib's:

*  :meth:`~pcapkit.corekit.enum.EnumLookup.get` raises
   :exc:`~pcapkit.utilities.exceptions.EnumKeyError` for a **name** miss and
   :exc:`~pcapkit.utilities.exceptions.EnumValueError` for a **value** miss, both
   from :mod:`pcapkit.utilities.exceptions` rather than from builtins.
*  The split between the two is not taste. ``E['nosuch']`` raises :exc:`KeyError`
   and ``E(999)`` raises :exc:`ValueError` on a stdlib :class:`~enum.Enum`, so a
   miss by name is :exc:`KeyError`-derived here and a miss by value is
   :exc:`ValueError`-derived, matching it.
*  That is what keeps the ruling cheap to carry out:
   :exc:`~pcapkit.utilities.exceptions.EnumKeyError` derives :exc:`KeyError` and
   :exc:`~pcapkit.utilities.exceptions.EnumValueError` derives :exc:`ValueError`,
   so **only the provenance changed** -- every ``except KeyError`` and
   ``except ValueError`` around a lookup keeps catching, in this tree and in a
   caller's.

Do not "improve" on the shape by making both misses report identically. Converting
one into the other is exactly what #923 retired, and it was retired in three places
at once: ``TransportProtocol.get`` and ``Criticality.get`` had each turned the
base's :exc:`KeyError` into a :exc:`ValueError`, and
:meth:`~pcapkit.protocols.internet.mh.FastBindingAcknowledgmentStatus.get` raised
:exc:`~pcapkit.utilities.exceptions.EnumValueError` for a name miss so that "the
two ways of getting it wrong reported identically".

One asymmetry between the two is deliberate and is **not** visible from the
exception class: the **name** miss is raised quietly
(:class:`~pcapkit.utilities.exceptions.BaseError`'s ``quiet=True``, so nothing is
logged and :data:`sys.tracebacklimit` is left alone) while the **value** miss stays
loud. A name miss is in-library control flow at several call sites, and at
:meth:`~pcapkit.const.http.method.Method.get` it is part of a *successful* call --
that override catches it in order to mint. A loud error there would put a
:data:`logging.CRITICAL` record on every such call and set
:data:`sys.tracebacklimit` to ``0`` process-wide, which is the
`#362 <https://github.com/JarryShaw/PyPCAPKit/issues/362>`__ defect ``quiet``
exists for. So a ``get`` override that catches a name miss as control flow is
following the convention; one that catches a *value* miss that way is silencing a
logged error, and needs a reason.

Case Sensitivity Is RFC-Directed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The rule, in the owner's own wording on
`#877 <https://github.com/JarryShaw/PyPCAPKit/issues/877>`__:

   if RFC states the values are case-insensitive, then our enum should also treat them
   that way. otherwise, we should treat them case sensitive.

And the reason a registry's spelling is never quietly normalised, from the same thread:
*"enum should honour and keep their original writings as in the registrars. case
in-sensitivity only applies to certain selected ones, where logically it makes sense
(like ``TransportProtocol``) and/or RFC documentation itself recognises them as
case-insensitive (like, maybe, FTP/HTTP commands)."*

So :meth:`~pcapkit.corekit.enum.EnumLookup.get` is **case-sensitive**, and that is the
default every enumeration gets. Case-insensitivity is a per-class ``get`` override that
has to cite the RFC or IANA registry making the values case-insensitive; without one it
is a defect rather than a convenience. That also means no public member is ever renamed
to make a lookup work -- which is what keeps
:class:`~pcapkit.const.hip.parameter.Parameter`'s ``R1_Counter = 128`` and
``R1_COUNTER = 129``, two IANA-registered HIP parameters differing only in case, both
resolvable.

And a folding override carries **only** the fold. ``TransportProtocol.get`` is the
worked example: since
`#923 <https://github.com/JarryShaw/PyPCAPKit/issues/923>`__ it lowers ``key``,
forwards ``default`` verbatim and delegates to ``super().get()``, and that is all it
does. It used to convert the base's name-miss :exc:`KeyError` into a
:exc:`ValueError` as well, and #923's ruling retired that; the
`#836 <https://github.com/JarryShaw/PyPCAPKit/pull/836>`__ refusal to extend the
class at all is untouched by the retirement, since only the exception class moved.
``Criticality.get`` went further and no longer exists: conversion was the *only*
thing it added over the base, so once that went there was nothing left for an
override to hold, and the class inherits
:meth:`~pcapkit.corekit.enum.EnumLookup.get` unchanged. **An override that would
now be empty is deleted, not kept as a pass-through** -- a ``get`` that only calls
``super().get()`` reads as though it were doing something, and the next reader has
to diff it against the base to find out that it is not.

The Lenient Criterion, in Two Limbs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ruling above leaves one question open, and
`#903 <https://github.com/JarryShaw/PyPCAPKit/issues/903>`__ settled it: does a
specification have to state a **comparison rule** for a registry to be treated
case-insensitively, or does it also count when the authorities merely **disagree
about spelling**? The owner's answer, verbatim:

   I say lenient. TransportProtocol for example should be case-insensitive. Upper or
   lower cases are being used everywhere in RFC and IANA themselves so that's an
   indication of case insensitivity.

So the test a new registry has to pass has **two limbs**, and satisfying either one
justifies case-insensitivity:

1. **A comparison rule in the governing document.** :rfc:`959#section-4.1` for FTP
   command codes, :rfc:`5797#section-2` for FTP FEAT codes, :rfc:`6335#section-5.1`
   for IANA service names.
2. **A documented spelling disagreement between the specification and the registry.**
   If the RFC writes a field one way throughout and the live IANA data writes it
   another, then neither authority is treating case as significant, and a lookup that
   does would reject a caller holding the spec's own spelling.

Limb 2 has to be **measured, not assumed** -- count the casings in the registry the
crawler actually reads, and say how many rows carried each. A guess about which way
IANA spells a column is not evidence.

Where neither limb holds, the lookup is case-sensitive and inherits
:meth:`~pcapkit.corekit.enum.EnumLookup.get` unchanged.

The Audit, per Class
~~~~~~~~~~~~~~~~~~~~

`#903 <https://github.com/JarryShaw/PyPCAPKit/issues/903>`__'s sweep, so that a
registry added later has something to check itself against. The owner's scope for it,
verbatim: *"we should audit all registries and then decide if case (in)sensitive."*

The population it covers, with the counting convention spelled out because the
figures move: **127** :class:`~pcapkit.corekit.enum.EnumRegistry` subclasses, every
one of them under :mod:`pcapkit.const`, across 124 files -- 117 :class:`int`-valued
(of which 5 are flag registries) and 10 :class:`~aenum.StrEnum`-valued. Plus **24**
non-registry enumerations counted by a runtime walk over both the :mod:`enum` and
:mod:`aenum` flavours and including nested classes: 17 top level (3 of them under
:mod:`pcapkit.const` itself) and 7 nested, the nested ones being
``FrameType.Flags`` in :mod:`pcapkit.protocols.schema.application.httpv2` plus its
6 concrete per-frame subclasses. 151 enumerations in total.

**The** :class:`int`\ **-valued tier, all 117, is case-sensitive, and the criterion is
vacuous on it rather than merely unmet.** A registry whose values are numbers has
nothing for case to apply to; the only way a string reaches
:meth:`~pcapkit.corekit.enum.EnumLookup.get` on one is as a member *name*, and a name
is the Python identifier :meth:`pcapkit.vendor.default.Vendor.safe_name` derives from
the registry's own name column -- it preserves the registrar's casing exactly, but it
is not itself a value any specification states a comparison rule for. Measured across
all 151 enumerations: exactly **one** would collide if names were folded --
:class:`~pcapkit.const.hip.parameter.Parameter`, on ``R1_Counter`` against
``R1_COUNTER`` -- and **no** enumeration anywhere has two ``str`` *values* that
collide when folded. So folding names is not merely unjustified, it is unsafe in a
measured case; folding values is safe but unjustified except where the table below
says otherwise.

That leaves the classes with something to decide:

.. list-table::
   :header-rows: 1
   :widths: 22 20 40 18

   * - Class
     - Governing source
     - What it says
     - Verdict
   * - :class:`~pcapkit.const.ftp.command.Command`
     - :rfc:`959#section-4.1`
     - *"Upper and lower case alphabetic characters are to be treated
       identically."* Limb 1.
     - **case-insensitive** -- ``get``/``_missing_`` fold, correctly
   * - :class:`~pcapkit.const.ftp.command.FEATCode`
     - :rfc:`5797#section-2`, :rfc:`2389#section-3.2`
     - *"IANA maintains uniqueness of feature names (FEAT codes) based on
       case-insensitive comparison."* Limb 1. Limb 2 holds too: RFC 2389 recommends
       upper case on the wire while the registry spells 5 of its 15 codes lower case
       (measured: of 64 rows, 11 upper-case / 10 distinct, 52 lower-case / 5
       distinct, 1 blank, 0 mixed). Read §3.2 to the end before concluding it
       disagrees: it *opens* by calling the feature-label *"nominally case
       sensitive"*, then defers to *"the definitions of specific labels"*, which
       RFC 5797 §2 above is. Note also that the §2 sentence is wrapped across a
       line break in the RFC's text file, at ``case-`` / ``insensitive``, so a
       line-oriented grep for the phrase finds nothing.
     - **case-insensitive** -- was a defect; ``get`` now folds
   * - :class:`~pcapkit.const.http.method.Method`
     - :rfc:`9110#section-9.1`
     - *"The method token is case-sensitive."* Explicitly the opposite of limb 1.
     - **case-sensitive** -- was a defect, fixed by
       `#896 <https://github.com/JarryShaw/PyPCAPKit/issues/896>`__
   * - :class:`~pcapkit.const.pcapng.option_type.OptionType`
     - ``draft-tuexen-opsawg-pcapng``
     - Nothing states a rule; the draft never discusses option-name case.
     - **case-sensitive** -- already exact-matches, conforms
   * - :class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel`
     - :rfc:`9850#section-4.2`
     - Nothing states a rule. Limb 2 fails on measurement: all 10 rows of the RFC's
       table and all 10 of the live IANA CSV are upper case, so the authorities
       agree. (RFC 9850 notes the labels *"correspond to lowercase labels in the TLS
       key schedule"*, but those are a different document's secret names, not a
       second spelling of the log label.)
     - **case-sensitive** -- no override, conforms
   * - ``TransportProtocol``
     - :rfc:`6335#section-8.1.1`
     - Nothing states a rule for the ``Transport Protocol`` field -- only *"limited
       to one or more of TCP, UDP, SCTP, and DCCP"*. Limb 2 carries it: the RFC and
       its §10.2 templates write the field upper case, the live CSV is lower case in
       all 14,536 rows (``tcp`` 6608, ``udp`` 6357, blank 1467, ``sctp`` 93,
       ``dccp`` 11, zero upper-case).
     - **case-insensitive** -- ``get`` folds, and this is the owner's own example.
       Folding is now the *only* thing that override adds (#923)
   * - :class:`~pcapkit.const.reg.apptype.apptype.AppType`
     - --
     - Moot: its ``get`` takes a port number and refuses a non-:class:`int` outright,
       so there is no string to fold. It does inherit the row above through
       ``_dispatch``, which resolves a ``proto`` string via ``TransportProtocol.get``.
     - **n/a** -- int-keyed
   * - ``TCP``, ``UDP``, ``SCTP``, ``DCCP``
     - :rfc:`6335#section-5.1`
     - *"case is ignored for comparison purposes, so both "http" and "HTTP" denote
       the same service."* Limb 1, emphatically -- and these registries' **values
       are** service names.
     - **unimplemented** -- no service-name lookup exists to fold; see below
   * - ``CommandType``, ``ConformanceRequirement``
     - :rfc:`959#section-4.1`, :rfc:`5797#section-2`
     - Limb 2 holds on measurement: the RFC and registry pages present the kind and
       conformance letters upper case (``A``/``P``/``S``, ``M``/``O``/``H``) while
       the CSV columns the crawler reads are lower case in every row (``s`` 26,
       ``a`` 18, ``s/p`` 3, blank 1; ``o`` 28, ``m`` 27, ``h`` 7, ``m [1]`` 2).
     - **open** -- see below
   * - The 5 :mod:`~pcapkit.protocols.internet.mh` and
       :mod:`~pcapkit.protocols.application.ngap` helper enumerations
     - IANA Mobility Header registries, 3GPP TS 38.413
     - Their values are numeric codes, so the criterion is vacuous exactly as for the
       :class:`int` tier above. **Two** of them define a ``get`` of their own --
       ``FastBindingAcknowledgmentStatus`` and ``IPv6AddressPrefixCode`` -- for
       signature reasons (no ``default``, and an :class:`int`/:class:`str` dispatch)
       rather than for case: each does an exact ``Cls[key]``, and since #923 each
       answers a name miss with
       :exc:`~pcapkit.utilities.exceptions.EnumKeyError` rather than
       :exc:`~pcapkit.utilities.exceptions.EnumValueError`. ``LMAAddressCode`` and
       ``LocalizedRoutingStatus`` carry no ``get`` at all, so they have no string
       lookup to fold. ``Criticality`` had one when this audit was taken and no
       longer does: #921 re-parented it onto
       :class:`~pcapkit.corekit.enum.EnumLookup` and #923 retired the exception
       conversion that was the override's only remaining job, so it now inherits
       ``get`` unchanged.
     - **case-sensitive** -- conforms
   * - ``WireGuardKeyLabel``
     - ``draft-tuexen-opsawg-pcapng``
     - The draft names the four labels outright (*"The key type is one of
       LOCAL_STATIC_PRIVATE_KEY, ..."*) and, as for ``OptionType`` above, never
       discusses their case. Both authorities write them upper case.
     - **case-sensitive** -- no override, conforms
   * - Every other non-registry enumeration
     - --
     - pcapkit's own discriminators and bit labels, with no registrar behind them
       at all -- ``Completion``, ``ftp.Type``, ``httpv1.Type``, ``FinalisedState``,
       ``ESPStatus``, ``PacketDirection``, ``PacketReception``, and the 7 httpv2
       ``Flags``. ``PDUKind`` is the one with an external source and it points the
       same way: its values are ASN.1 identifiers from 3GPP TS 38.413, and ASN.1
       identifiers are case-significant by construction.
     - **case-sensitive** -- nothing to cite, nothing to change

Two rows the audit deliberately left open rather than acting on, because each is
wider than a case fix:

* **A service-name lookup on the** ``AppType`` **transport registries.** This is the
  inverse of every other row: :rfc:`6335#section-5.1` *does* make service names
  case-insensitive, and ``TCP``/``UDP``/``SCTP``/``DCCP`` hold service names as their
  values -- but ``AppType.get`` refuses a non-:class:`int` key, so no service-name
  lookup exists for the rule to apply to. Implementing one is new public API on a
  6,000-member registry where one name maps to many ports, which is a ``get_all``
  design question rather than a case fold.
* ``CommandType`` **and** ``ConformanceRequirement``. By parity with
  ``TransportProtocol`` -- an :class:`int`-valued enumeration whose *names* are the
  specification's own tokens -- the measured spelling disagreement above would make
  these two case-insensitive. Nothing looks them up by string today, though: the
  crawler translates the CSV's lower-case letters to the upper-case member names at
  generation time, and neither class inherits
  :class:`~pcapkit.corekit.enum.EnumLookup` yet -- both are in the seven phase 2 has
  not reached, per the note above. Re-parenting them is phase 2 of
  `#877 <https://github.com/JarryShaw/PyPCAPKit/issues/877>`__, which is where the
  question belongs.

One case fold also lives **outside** any ``get``, and so escapes this convention
entirely: ``_resolve`` in :mod:`pcapkit.protocols.internet.esp` upper-cases its
``value`` before matching it against :class:`~pcapkit.const.esp.cipher.Cipher` and
:class:`~pcapkit.const.esp.integrity.Integrity` member names. :rfc:`7296` states no
comparison rule for IKEv2 transform names -- checked, it does not discuss case at all
-- so that fold is a convenience with no citation behind it. It is a protocol-level
resolver rather than a registry override, which is why the audit records it here
rather than changing it.

.. note::

   The obstacle this page used to record -- that the base's string-key path does not
   fall through to a value lookup, so a :class:`~aenum.StrEnum` registry would stop
   resolving a valid value that is not also a name -- **no longer applies.**
   :meth:`~pcapkit.corekit.enum.EnumLookup.get` now checks ``_value2member_map_``
   when the name lookup misses, so such a value resolves:

   .. code-block:: pycon

      >>> FEATCode['base'].value
      '<base>'
      >>> '<base>' in FEATCode._member_map_
      False
      >>> FEATCode.get('<base>')
      <FEATCode [base]>

   The example above is :class:`~pcapkit.const.ftp.command.FEATCode`'s shape, and it
   still resolves exactly as shown -- but since
   `#903 <https://github.com/JarryShaw/PyPCAPKit/issues/903>`__ that class overrides
   ``get`` too, so the output is only the base's because its override delegates an
   exact name-or-value hit straight through. Measure the base on a registry that does
   **not** override ``get`` at all. **Five** do --
   :class:`~pcapkit.const.ftp.command.Command`,
   :class:`~pcapkit.const.ftp.command.FEATCode`,
   :class:`~pcapkit.const.http.method.Method`,
   :class:`~pcapkit.const.pcapng.option_type.OptionType` and
   :class:`~pcapkit.const.reg.apptype.apptype.AppType` -- and probing one of those
   measures the override rather than the base. The unconditionally clean witness is
   ``tests/corekit/test_enum_lookup_base_unit.py``'s own ``_Str``, a purpose-built
   closed set carrying ``angled = '<angled>'`` precisely so that the value
   fall-through can be measured on a class that defines no ``get``.
   ``Command.get`` upper-cases its key
   before matching, which makes it look as though the base were case-insensitive --
   deliberately, since :rfc:`959#section-4.1` treats FTP command codes identically
   regardless of case. ``Method.get`` used to fold case the same way, but
   `#896 <https://github.com/JarryShaw/PyPCAPKit/issues/896>`__ made it
   case-sensitive instead: :rfc:`9110#section-9.1` says the HTTP method token is
   case-sensitive, so ``Method.get('get')`` no longer resolves to
   ``Method.GET`` -- it builds its own unregistered member, preserving the
   caller's exact casing, the same way an unrecognised value always does.

What does survive is narrower and deliberate: a **declared-but-unassigned** ``str``
value resolves through ``cls(value)`` but not through ``get(value)``, because
:meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member` returns it without
growing either lookup table. ``FEATCode.get('ZZ-NOT-REAL')`` raises
:exc:`~pcapkit.utilities.exceptions.EnumKeyError` -- which *is* a :exc:`KeyError`, so
an ``except KeyError`` around it is unaffected -- while
``FEATCode('ZZ-NOT-REAL')`` yields an unregistered member. Closing that gap would
mean calling ``cls(key)`` for a ``str`` value too, which reopens the minting hazard
above -- so the asymmetry is intended, and ``get``'s own docstring carries the full
reasoning.

.. seealso::

   :mod:`pcapkit.vendor` generates these modules. A change to the shape of a
   generated registry belongs in the crawler or in
   :mod:`pcapkit.vendor.default`'s template, never in the generated file alone --
   the next regeneration would discard it.

.. _extension-header-subclassing:

Which bases an IPv6 extension header names
------------------------------------------

Every IPv6 extension header in this package subclasses
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`. Some name a **second** base
as well, and which ones do is a ruling rather than an accident. The owner's words,
on `#924 <https://github.com/JarryShaw/PyPCAPKit/pull/924>`__:

   I think on subclassing, we might wanna keep this convention: if the IPv6
   extension header is only usable as an extension header, then it only inherit
   from ``IPv6_Ext``, like ``IPv6_Frag``; but if it is useable as a standalone
   protocol itself, then it herit from both ``IPv6_Ext`` and ``Internet`` (or
   ``IPsec``), like ``ESP``.

The family as it stands:

.. list-table::
   :header-rows: 1
   :widths: 34 30 36

   * - Header
     - Bases
     - Classification
   * - :class:`~pcapkit.protocols.internet.hopopt.HOPOPT`,
       :class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route`,
       :class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`,
       :class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`,
       :class:`~pcapkit.protocols.internet.mh.MH`
     - ``IPv6_Ext``
     - extension-header only
   * - :class:`~pcapkit.protocols.internet.ah.AH`,
       :class:`~pcapkit.protocols.internet.esp.ESP`
     - ``IPsec``, ``IPv6_Ext``
     - **also standalone**
   * - :class:`~pcapkit.protocols.internet.hip.HIP`
     - ``IPv6_Ext``, ``Internet``
     - **also standalone**

:class:`~pcapkit.protocols.internet.ipsec.IPsec` is itself an
:class:`~pcapkit.protocols.internet.internet.Internet` subclass, which is the
parenthetical *"(or* ``IPsec``\ *)"* in the ruling: naming it satisfies the
convention, and it is the right second base for a header whose standalone form is an
IPsec one.

The code cannot be used as evidence
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**This is the part a future reader will get wrong, so it is stated before the
criterion itself.** The obvious way to decide whether a header is "usable as a
standalone protocol" is to ask what the library's own dispatch already allows. That
answer is useless, and measurably so:

.. code-block:: pycon

   >>> from pcapkit.protocols.internet.ipv4 import IPv4
   >>> from pcapkit.protocols.internet.internet import Internet
   >>> IPv4.__proto__ is Internet.__proto__
   True

The protocol-number registry is **one shared object**, so *every* extension header
is reachable as an IPv4 payload in this library --
:class:`~pcapkit.protocols.internet.hopopt.HOPOPT` and
:class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag` included. Registry
membership therefore says nothing at all about standalone-ness, and a classification
derived from it would make all eight headers standalone.

Nor does IANA's *IPv6 Extension Header Types* registry discriminate: it lists all
eight of the implemented headers, plus ``Shim6`` (140) and 253/254. Being *in* that
registry is what makes something an extension header; it is not evidence about
whether the same header is also a protocol in its own right.

The operative test is what the RFCs say
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

So the census is read out of the specifications, on the owner's instruction:

   So my suggestion is to read through the RFCs to figure out any of the defined
   IPv6 extension headers are extension header only or standalone protocol as well.
   Then we can decide if they should inherit only ``IPv6_Ext`` or additional bases.

And the limb that decides is **whether a primary source shows the header carried
directly as an IPv4 payload**:

*  :class:`~pcapkit.protocols.internet.ah.AH` -- :rfc:`4302#section-3.1.1`, *"In the
   context of IPv4, this calls for placing AH after the IP header"*, with a
   before-and-after IPv4 diagram.
*  :class:`~pcapkit.protocols.internet.esp.ESP` -- :rfc:`4303#section-3.1.1`, the
   same sentence and the same diagram for ESP.
*  :class:`~pcapkit.protocols.internet.hip.HIP` -- :rfc:`7401#appendix-C.2`,
   *"IPv4 HIP Packet (I1 Packet)"*, whose worked checksum is over an IPv4 header
   carrying ``Next Header: 139``. :rfc:`7401#section-5.1` also calls the HIP header
   *"logically an IPv6 extension header"*, so HIP is genuinely both.

:class:`~pcapkit.protocols.internet.mh.MH` is the instructive failure, because it
**is** a protocol in its own right and still does not qualify:
:rfc:`6275#section-6.1.1` defines its checksum over a pseudo-header of *"IPv6 header
fields"* whose addresses are *"the addresses that appear in the Source and
Destination Address fields in the IPv6 packet carrying the Mobility Header"* -- there
is no IPv4 variant of that computation -- and the IPv4 equivalent function is not
protocol 135 at all, since :rfc:`5944` carries Mobile IPv4 over UDP port 434.
``Shim6`` (140) has the same shape and the same verdict; this package has never had a
parser class for it, so nothing implements the classification, but a future one
inherits :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` alone.

.. important::

   Own-protocolhood on its own is **not** sufficient, and MH is the case that
   settles it: the alternative reading -- that a protocol in its own right qualifies
   whether or not it can appear under IPv4 -- was put to the owner explicitly on
   `#924 <https://github.com/JarryShaw/PyPCAPKit/pull/924>`__ and not taken, so MH
   and ``Shim6`` stay extension-only. A header that is a protocol in its own right
   but structurally cannot be an IPv4 payload names ``IPv6_Ext`` alone.

The declaration is what carries the classification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Name the second base **explicitly**, even though it is already in the MRO.
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` derives
:class:`~pcapkit.protocols.internet.internet.Internet`, so every one of the eight
reaches ``Internet`` transitively and an ``__mro__`` check cannot tell the two groups
apart. The declaration is the only place the classification exists, which is why
``tests/protocols/internet/test_ipv6_ext_unit.py`` pins it against ``__bases__``:

.. code-block:: python

   STANDALONE_MEMBERS = frozenset({'AH', 'ESP', 'HIP'})

Add a header to that set in the same change that adds its second base, and keep the
RFC ground in the ``#:`` comment beside it. The test walks
``IPv6_Ext.__subclasses__()`` rather than a hard-coded list, so a ninth header is
held to the convention whether or not anyone remembers this page.

The base is named ``IPv6_Ext``, and nothing else
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The class arrived as ``IPv6_GenericExt``, a fallback parser for an unrecognised
extension header (`#891 <https://github.com/JarryShaw/PyPCAPKit/issues/891>`__), and
`#917 <https://github.com/JarryShaw/PyPCAPKit/issues/917>`__ merged that role with
the shared-base role into one class under the shorter name. No compatibility alias
was left behind, and that was deliberate. The owner's ruling:

   No more ``IPv6_GenericExt`` name. Its an intermediate state and never released.

The reasoning is what makes it safe rather than merely decided: the old name existed
on ``main`` from ``b3551cb63`` to ``93cf940b3`` -- under four hours on one day, and
after the most recent release tag -- so it appears in **no** release, and the break
has no callers to inconvenience. Do not reintroduce it as an alias, and do not cite
it in prose as a former public name; it was never one.

ESP is an extension header, and still cannot short-circuit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two facts about :class:`~pcapkit.protocols.internet.esp.ESP` coexist, and each is
routinely mistaken for a refutation of the other.

**It is an extension header.** IANA's *IPv6 Extension Header Types* registry lists
protocol number **50**, and this package's
:class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` agrees (``ESP = 50``).
:rfc:`8200#section-4.5` appears to say otherwise -- *"the Encapsulating Security
Payload (ESP) is not considered an extension header"* -- but that sentence opens
*"For this purpose,"*, scoping it to the fragmentation discussion it sits in, and the
sentence after it lists ESP among *"examples of upper-layer headers"*. The library
follows the registry, on the owner's ruling for
`#895 <https://github.com/JarryShaw/PyPCAPKit/issues/895>`__, which is why ESP
carries the same extension-mode contract as its siblings.

**And it terminates the chain walk.** :rfc:`4303` places ESP's Next Header byte
inside the *encrypted* trailer, so with no key material there is nothing to continue
on: ESP's own data model reports ``next`` as :obj:`None`, and
:meth:`IPv6._decode_next_layer <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`
ends the ordinary way one iteration later. So ESP is absent from
``IPv6.__generic_ext_codes__`` -- not because it lacks a parser, which it has, but
because it cannot hand the walk a successor.

The full reasoning, including how ESP's terminal case differs from 253/254's, is
written where the code is and is deliberately not restated at length here: see the
``#:`` comment on ``IPv6.__generic_ext_codes__``
(:file:`pcapkit/protocols/internet/ipv6.py`) and the module docstring of
:mod:`pcapkit.protocols.internet.ipv6_ext`.

.. caution::

   The two facts have to be kept apart when reading any of this. "ESP is not an
   extension header" (wrong, and :rfc:`8200#section-4.5` quoted out of scope) is a
   different claim from "ESP cannot be walked past" (right, and about
   :rfc:`4303`'s wire format). Collapsing them is how ESP ends up either dropped
   from the extension-header contract or wrongly added to the generic-dispatch set.
