Registry Conventions
====================

.. important::

   This page records **design rulings** for :mod:`pcapkit.const` -- decisions that
   are not derivable from the code, and that a future maintainer or an automated
   contributor would otherwise have to rediscover by reading a closed issue
   thread. Each ruling names where it was settled.

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
three in the tree follow it:

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Instance
     - Type
     - Defined in
   * - ``NULL``
     - ``NullType``
     - :mod:`pcapkit.corekit.module`
   * - ``NoValue``
     - ``NoValueType``
     - :mod:`pcapkit.corekit.fields.field`
   * - ``NO_DEFAULT``
     - ``NoDefaultType``
     - :mod:`pcapkit.corekit.enum`

Note what the rule does **not** fix: the **instance** name's casing is deliberately
free, which is why ``NULL`` and ``NoValue`` disagree and both are correct. Pick
whichever reads better at the call site, and where a name already exists, keep it --
renaming a published sentinel costs every caller for no gain.

.. note::

   Of the three, only :class:`~pcapkit.corekit.module.NullType` is a full worked
   example. ``NoValueType`` follows the naming rule but is **not** a singleton
   (``NoValueType() is NoValue`` is :obj:`False`) and has no ``__repr__`` of its own,
   so it demonstrates the name and nothing else. Copy ``NullType`` when you need a
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

What to implement, and what not to
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The three sentinels deliberately differ, and the differences are **needs, not
inconsistencies**:

``__new__`` returning a cached instance
   Guards against a caller constructing a second, non-identical sentinel that then
   fails every ``is`` check. Worth having wherever the type is exported.
   :class:`~pcapkit.corekit.module.NullType` documents the limit honestly: a module
   **reload** re-executes the class statement, so the guard does not survive one, and
   code holding the pre-reload instance will fail ``is``.

``__bool__`` returning :obj:`False`
   ``NULL`` and ``NoValue`` have it, because each stands for an *absent value* and
   reads naturally in a boolean test. ``NO_DEFAULT`` deliberately does **not**: it is a
   marker meaning *no default was supplied*, it is only ever tested with ``is``, and
   making it falsy would invite ``if not default:`` -- which would then treat a
   caller's genuine falsy default (``0``, ``''``, :obj:`None`, :obj:`False`) the same
   as the sentinel, the very confusion the sentinel exists to prevent.

``__copy__`` / ``__deepcopy__`` / ``__reduce__``
   :class:`~pcapkit.corekit.module.NullType` has them because ``NULL`` is stored in a
   :class:`~pcapkit.corekit.module.ModuleDescriptor` field, so a caller's
   :func:`copy.deepcopy` or :mod:`pickle` can walk into it and would otherwise
   reconstruct a second instance. ``NO_DEFAULT`` has none, because it is never stored
   in any structure a caller copies -- it only ever appears as a default argument.
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
* **A** ``str`` **key never reaches it.** That path never calls ``cls(key)``, so it
  resolves only against already-populated lookup tables, where every value present is
  legal by construction. ``register`` does call it, after its duplicate check.

.. note::

   Re-parenting the remaining helper enumerations onto
   :class:`~pcapkit.corekit.enum.EnumLookup` is **phase 2** of
   `#877 <https://github.com/JarryShaw/PyPCAPKit/issues/877>`__ and has not happened
   yet. Phase 1 is deliberately behaviour-preserving on its own, which is what let it
   land while other work was still in flight on the files the re-parent touches.

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

.. note::

   Auditing every registry's existing case behaviour against the specification its
   values come from is `#903 <https://github.com/JarryShaw/PyPCAPKit/issues/903>`__,
   not something this page records per class. The owner's scope for it, verbatim:
   *"we should audit all registries and then decide if case (in)sensitive."* Two
   findings already have their own issues --
   :class:`~pcapkit.const.ftp.command.Command`'s ``value.upper()`` is backed by
   :rfc:`959#section-4.1` (*"Upper and lower case alphabetic characters are to be
   treated identically"*), while
   :class:`~pcapkit.const.http.method.Method`'s ``key.upper()`` contradicts
   :rfc:`9110#section-9.1`, which makes the method token case-sensitive, and is tracked
   as `#896 <https://github.com/JarryShaw/PyPCAPKit/issues/896>`__.

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

   Measure it on a registry that does **not** override ``get``. Four do --
   :class:`~pcapkit.const.ftp.command.Command`,
   :class:`~pcapkit.const.http.method.Method`,
   :class:`~pcapkit.const.pcapng.option_type.OptionType` and
   :class:`~pcapkit.const.reg.apptype.apptype.AppType` -- and probing one of those
   measures the override rather than the base. ``Command.get`` upper-cases its key
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
growing either lookup table. ``FEATCode.get('ZZ-NOT-REAL')`` raises :exc:`KeyError`
while ``FEATCode('ZZ-NOT-REAL')`` yields an unregistered member. Closing that gap would
mean calling ``cls(key)`` for a ``str`` value too, which reopens the minting hazard
above -- so the asymmetry is intended, and ``get``'s own docstring carries the full
reasoning.

.. seealso::

   :mod:`pcapkit.vendor` generates these modules. A change to the shape of a
   generated registry belongs in the crawler or in
   :mod:`pcapkit.vendor.default`'s template, never in the generated file alone --
   the next regeneration would discard it.
