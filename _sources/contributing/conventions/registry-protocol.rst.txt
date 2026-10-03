.. _registry-protocol:

The Registry Protocol
---------------------

:meth:`~pcapkit.corekit.enum.EnumLookup.get`,
:meth:`~pcapkit.corekit.enum.EnumLookup.get_all`,
:meth:`~pcapkit.corekit.enum.EnumRegistry.register` and
:meth:`~pcapkit.corekit.enum.EnumRegistry.register_alias` are expected to exist on
**every** registry, per the ruling on
:issue:`842`. They come from
:class:`~pcapkit.corekit.enum.EnumRegistry`, mixed in ahead of the enum base so that
``_member_type_`` still resolves to :class:`int` or :class:`str`:

.. code-block:: python

   class LinkType(EnumRegistry, IntEnum):
       ...

Six registries define their own ``__new__`` to carry extra attributes and so do not
share the generated template: :class:`~pcapkit.const.ftp.command.Command`,
:class:`~pcapkit.const.ftp.return_code.ReturnCode`,
:class:`~pcapkit.const.http.method.Method`,
:class:`~pcapkit.const.http.status_code.StatusCode`,
:class:`~pcapkit.const.pcapng.option_type.OptionType` and
:class:`~pcapkit.const.reg.apptype.apptype.AppType`. They are on the base regardless --
:issue:`860` finished that -- so a
bespoke ``__new__`` exempts a registry from the template, not from the protocol.

The Two-Tier Hierarchy
~~~~~~~~~~~~~~~~~~~~~~

:class:`~pcapkit.corekit.enum.EnumRegistry` is not the only base any more. Since
phase 1 of :issue:`877` it has a
parent, and the line between them is whether the enumeration may *grow*:

=================================================== ==============================================================
:class:`~pcapkit.corekit.enum.EnumLookup`           ``get``, ``get_all``, ``_validate_value``
:class:`~pcapkit.corekit.enum.EnumRegistry`         ``register``, ``register_alias``, ``register_aliases``,
                                                    ``_extend``, ``_unregistered_member``
=================================================== ==============================================================

The owner ruled on :issue:`877` that a registry may subclass a bare base enum out of
:mod:`pcapkit.corekit.enum`, with :class:`~pcapkit.corekit.enum.EnumRegistry`
subclassing that base in turn for use by the mutable ones. So a **closed** set
inherits :class:`~pcapkit.corekit.enum.EnumLookup`
directly and is never handed a ``register`` it would have to refuse; an **open**
registry inherits :class:`~pcapkit.corekit.enum.EnumRegistry` exactly as before.

What settled the split is the owner's own second thought about carrying ``register``
on the base: if the base carries ``register``, there is no principled reason for it
not to carry ``register_alias`` as well, and the ruling would be the worse for it.
Following that through leaves :class:`~pcapkit.corekit.enum.EnumRegistry` holding only
three methods, too thin to justify a second class -- so the two tiers collapse into one,
which is the opposite of what was ruled.

**Both tiers are plain classes, and that is load-bearing.** Inserting a parent above
:class:`~pcapkit.corekit.enum.EnumRegistry` leaves the member data type exactly where
it was -- ``LinkType -> EnumRegistry -> EnumLookup -> IntEnum -> int`` -- so
``_member_type_`` still comes from the enum base. Had either tier subclassed
``aenum.Enum`` in order to "be an enum", it would have become the member type
itself and broken ``int``, ``str`` and flag registries at once.

:meth:`~pcapkit.corekit.enum.EnumLookup._validate_value` is what the base carries
*instead* of ``register``, and it answers the owner's other requirement: the base has
to offer range-validation logic for its inheriting classes to hook into. The
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
  and converts only ``aenum``'s and :mod:`enum`'s own "no member carries this
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

   Re-parenting every non-registry enumeration onto
   :class:`~pcapkit.corekit.enum.EnumLookup` was **phase 2** of
   :issue:`877`, and it is now
   **complete**: the phase landed for 24 of the 24 non-registry enumerations.
   **Zero enumerations remain outside the hierarchy**, measured by the same runtime
   walk over both the :mod:`enum` and ``aenum`` flavours that once found seven.

Failed-Lookup Exceptions
~~~~~~~~~~~~~~~~~~~~~~~~

Two rules govern which exception a failed lookup raises, and they pull in opposite
directions on purpose. The owner ruled on
:issue:`923` that the choice between
:exc:`ValueError` and :exc:`KeyError` follows whichever stdlib's :class:`~enum.Enum`
would raise in the same circumstance, and that whichever it is comes from
:mod:`pcapkit.utilities.exceptions` rather than from builtins.

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

Which branch a key takes, and what each miss ends in:

.. mermaid::

   flowchart TD
       GET["get(key, default)"] -->|"isinstance(key, str)"| NAME["_member_map_ lookup"]
       GET -->|"otherwise"| VALUE["_validate_value(key)<br/>then cls(key)"]
       NAME -->|"hit"| OK["canonical member"]
       NAME -->|"miss, key is a registered value"| OK
       NAME -->|"miss, default is a registered value"| OK
       NAME -->|"miss, no usable default"| KEYERR["EnumKeyError<br/>quiet, derives KeyError"]
       VALUE -->|"resolves, or _missing_ answers"| OK
       VALUE -->|"ValueError, default is a registered value"| OK
       VALUE -->|"ValueError, no usable default"| VALERR["EnumValueError<br/>loud, derives ValueError"]

Do not "improve" on the shape by making both misses report identically. Converting
one into the other is exactly what :issue:`923` retired, and it was retired in three
places at once: ``TransportProtocol.get`` and ``Criticality.get`` had each turned the
base's :exc:`KeyError` into a :exc:`ValueError`, and
``FastBindingAcknowledgmentStatus.get`` raised
:exc:`~pcapkit.utilities.exceptions.EnumValueError` for a name miss, so that the two
ways of getting it wrong reported identically.

One asymmetry between the two is deliberate and is **not** visible from the
exception class: the **name** miss is raised quietly
(:class:`~pcapkit.utilities.exceptions.BaseError`'s ``quiet=True``, so nothing is
logged and :data:`sys.tracebacklimit` is left alone) while the **value** miss stays
loud. A name miss is in-library control flow at several call sites, and at
``Method.get`` it is part of a *successful* call --
that override catches it in order to mint. A loud error there would put a
:data:`logging.CRITICAL` record on every such call and set
:data:`sys.tracebacklimit` to ``0`` process-wide, which is the
:issue:`362` defect ``quiet``
exists for. So a ``get`` override that catches a name miss as control flow is
following the convention; one that catches a *value* miss that way is silencing a
logged error, and needs a reason.

``get`` Override Obligations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Three rulings settled what an override owes
:meth:`~pcapkit.corekit.enum.EnumLookup.get`, and the last of them deleted two
overrides outright. They are collected here because each was reached by the same
argument: the base's contract is house-wide, so an override that diverges from it is
a defect rather than a local judgement about its own callers. The first item below is
not a ruling but a language constraint, recorded with them because the three rulings
all presuppose it.

**An override that delegates is a** ``@classmethod``, and this one is forced by
Python rather than decided. Zero-argument :func:`super` binds the enclosing
function's **first positional parameter** as its instance, whatever that parameter
is named -- so inside ``@staticmethod def get(key, default=NO_DEFAULT)`` it binds
``key``, the lookup key, and ``return super().get(key)`` fails on the key rather
than reaching the base. On Python 3.13 and newer::

   TypeError: super(type, obj): obj (instance of str) is not an instance or
   subtype of type (FastBindingAcknowledgmentStatus).

and on 3.10 through 3.12, where CPython words it differently and names neither the
instance nor the type::

   TypeError: super(type, obj): obj must be an instance or subtype of type

Both forms share ``instance or subtype of type``, which is the only part of the
message anything here relies on -- pinning either full sentence would pass on two of
the five supported versions and fail on the other three.

Two corollaries worth stating, because the obvious summary of this is wrong in both
directions. ``RuntimeError: super(): no arguments`` is a *different* failure, raised
only when the enclosing function takes no parameters at all -- no real ``get``
override qualifies, since every one takes ``key``. And the ``TypeError`` is not
guaranteed either: pass a first argument that *is* an instance of the class and the
delegation **silently succeeds**, so a ``@staticmethod`` override cannot even be
relied on to fail loudly. Measured, all three cases, rather than reasoned about.
:meth:`~pcapkit.corekit.enum.EnumLookup.get` is itself a ``@classmethod``. The
precedent is :issue:`903`, which made
``FEATCode.get`` a ``@classmethod def get(cls, key, default=NO_DEFAULT)`` ending in
``return super().get(key, default)``;
:issue:`908` followed it, which is
what turned ``Method.get`` into a classmethod.

Callers cannot see the switch -- ``Method.get('X')`` binds identically either way --
so there is no compatibility argument for keeping the ``@staticmethod``. Two
``@staticmethod`` overrides do survive and are still correct:
:class:`~pcapkit.const.ftp.command.Command`'s and
:class:`~pcapkit.const.pcapng.option_type.OptionType`'s never call ``super()`` at
all, so neither meets the condition.

**Raise the way the base raises, which means** ``quiet=True``.
:issue:`933` asked whether two
overrides raising :exc:`~pcapkit.utilities.exceptions.EnumKeyError` **without**
``quiet=True`` should adopt the base's. The owner first declined, then reversed
course: they should follow the house convention and not be loud.

Both answers are on the issue deliberately, and the reversal is the ruling. What it
settles is not the one keyword -- it is the tie-breaker. A loud
:class:`~pcapkit.utilities.exceptions.BaseError` sets :data:`sys.tracebacklimit` to
``0`` **process-wide**, the
:issue:`362` hazard, so loudness is
paid for by the whole library rather than by the override's own callers. The argument
against changing them was that ``quiet=True`` exists on the base for a name miss
inside a *successful* call at ``Method.get`` and these two had no such caller;
uniformity beat it, because a per-class judgement about present callers cannot price
a process-wide effect.

**A signature the base advertises has to be honoured, not suppressed.** Re-parenting
onto :class:`~pcapkit.corekit.enum.EnumLookup` gave those same two classes an
inherited two-argument ``get(key, default)`` that their one-argument overrides then
refused::

   FastBindingAcknowledgmentStatus.get('bogus', 'Handover_Accepted')
   TypeError: get() takes 1 positional argument but 2 were given

A ``# type: ignore[override] # pylint: disable=arguments-differ`` pair hid the
mismatch from ``mypy`` and ``pylint``, and both docstrings disclosed it in prose
instead. Put to the owner on
:issue:`935` as one of three options
-- widen and delegate, refuse ``default`` explicitly with an in-library error, or
leave the disclosure as the settled answer -- the first was the ruling. So
**a suppression plus a docstring is not an answer to a contract the class advertises
and breaks.** The check that the suppression was load-bearing is the one to repeat
before believing any such pair: stripping these two yielded
``Signature of "get" incompatible with supertype "EnumLookup"  [override]`` at both
lines, with ``--warn-unused-ignores`` reporting neither as unused.

**And an override that only reimplements the base is deleted, not repaired.** Widening
those two signatures made them faithful copies of the base. Rather than merge them,
the owner asked, in review of that same widening, why the two overrides needed to
exist at all, if they could simply fall back to the base's.

They could. Nine cases per class -- name hit, name miss, value hit, value miss and
every ``default`` combination -- differed from ``EnumLookup.get.__func__(cls, ...)``
in **zero** of them, and neither class carried an alias (``__members__`` 6 and 4,
``list(cls)`` 6 and 4) for the *"Backport support for original codes"* in their
docstrings to refer to. Offered the choice between merging the widened copies and
deleting them in a follow-up, the owner ruled for deleting them outright. Both
``get`` methods and both suppressions went with it, and
:mod:`pcapkit.protocols.internet.mh` now defines no ``get`` at all.

The one input where the copies **did** differ is why this matters beyond line count,
and it is the trap for whoever writes the next override: the base branches on
``isinstance(key, str)`` and treats everything else as a *value*, while those two
branched on ``isinstance(key, int)`` and fell through to the *name* path for anything
else. ``get(None)`` therefore raised a quiet
:exc:`~pcapkit.utilities.exceptions.EnumKeyError` on those two and a loud
:exc:`~pcapkit.utilities.exceptions.EnumValueError` on the other four of the six
locally-defined helpers in those two modules, and no prose
anywhere said so. Re-implementing the dispatch is how an override acquires a
divergence nobody wrote down; delegating to it is how it does not.

Taken with the ``Criticality.get`` deletion below -- an override emptied by :issue:`923`
rather than by redundancy -- the rule generalises: **an override justifies itself by
what it adds to the base, and goes when the answer is nothing.**

RFC-Directed Case Sensitivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The rule, as the owner ruled it on
:issue:`877`: where the RFC states the
values are case-insensitive, the enumeration treats them that way too; otherwise it
treats them as case-sensitive.

And the reason a registry's spelling is never quietly normalised, from the same thread:
an enumeration honours and keeps the original writing the registrar used, and
case-insensitivity applies only to the selected registries where it makes logical sense
-- ``TransportProtocol`` being one -- or where the RFC documentation itself recognises
the values as case-insensitive, FTP and HTTP commands being the candidates the owner
named. Only FTP survived the audit below: :rfc:`9110#section-9.1` makes the HTTP method
token case-sensitive outright.

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
:issue:`923` it lowers ``key``,
forwards ``default`` verbatim and delegates to ``super().get()``, and that is all it
does. It used to convert the base's name-miss :exc:`KeyError` into a
:exc:`ValueError` as well, and :issue:`923`'s ruling retired that; the
:issue:`808` refusal to extend the
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
:issue:`903` settled it: does a
specification have to state a **comparison rule** for a registry to be treated
case-insensitively, or does it also count when the authorities merely **disagree
about spelling**? The owner ruled for the lenient reading, with ``TransportProtocol``
as the example given: upper and lower casings are used throughout the RFCs and IANA's
own data, and that mixed usage is itself an indication of case-insensitivity.

So the test a new registry has to pass has **two limbs**, and satisfying either one
justifies case-insensitivity:

1. **A comparison rule in the governing document.** :rfc:`959#section-5` for FTP
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

:issue:`903`'s sweep, so that a
registry added later has something to check itself against. The owner set its scope:
audit every registry first, and decide case-sensitivity per registry from that.

The population it covers, with the counting convention spelled out because the
figures move: **127** :class:`~pcapkit.corekit.enum.EnumRegistry` subclasses, every
one of them under :mod:`pcapkit.const`, across 124 files -- 117 :class:`int`-valued
(of which 5 are flag registries) and 10 ``aenum.StrEnum``-valued. Plus **24**
non-registry enumerations counted by a runtime walk over both the :mod:`enum` and
``aenum`` flavours and including nested classes: 17 top level (3 of them under
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
     - :rfc:`959#section-5`
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
       :issue:`896`
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
       Folding is now the *only* thing that override adds (:issue:`923`)
   * - :class:`~pcapkit.const.reg.apptype.apptype.AppType`
     - --
     - Moot: its ``get`` takes a port number and refuses a non-:class:`int` outright,
       so there is no string to fold. It does inherit the row above through
       ``_dispatch``, which resolves a ``proto`` string via ``TransportProtocol.get``.
     - **n/a** -- int-keyed
   * - ``TCP``, ``UDP``, ``SCTP``, ``DCCP``
     - :rfc:`6335#section-5.1`
     - *"case is ignored for comparison purposes, so both "http" and "HTTP" denote
       the same service."* Limb 1, emphatically -- and these registries **derive every
       member name from the registry's service-name column**, in the registrar's own
       spelling (``tcpmux``); the *value* is a composite that embeds it
       (``'tcpmux [1 - tcp]'``), not the bare name.
     - **unimplemented** -- no service-name lookup exists to fold; see below
   * - ``CommandType``, ``ConformanceRequirement``
     - :rfc:`959#section-4`, :rfc:`5797#section-2`
     - Limb 2 holds on measurement: the RFC and registry pages present the kind and
       conformance letters upper case (``A``/``P``/``S``, ``M``/``O``/``H``) while
       the CSV columns the crawler reads are lower case in every row (``s`` 26,
       ``a`` 18, ``p`` 16, ``s/p`` 3, blank 1; ``o`` 28, ``m`` 27, ``h`` 7,
       ``m [1]`` 2). Both tallies cover all 64 rows.
     - **open** -- see below
   * - The 6 :mod:`~pcapkit.protocols.internet.mh` and
       :mod:`~pcapkit.protocols.application.ngap` helper enumerations
     - IANA Mobility Header registries, 3GPP TS 38.413
     - ``FastBindingAcknowledgmentStatus``, ``IPv6AddressPrefixCode``,
       ``LMAAddressCode``, ``LocalizedRoutingStatus``, ``Criticality`` and ``PDUKind``.
       **Five** of the six carry numeric codes, so the criterion is vacuous on them
       exactly as for the :class:`int` tier above; ``PDUKind``'s are :class:`str` ASN.1
       identifiers from 3GPP TS 38.413, and ASN.1 identifiers are case-significant by
       construction, so it lands the same way for a different reason.
       **None** of the six defines a ``get`` of its own any more. Two did when this
       audit was taken --
       ``FastBindingAcknowledgmentStatus`` and ``IPv6AddressPrefixCode``, for
       signature reasons (no ``default``, and an :class:`int`/:class:`str` dispatch)
       rather than for case -- and both were deleted as redundant rather than widened,
       on the ruling recorded in the section above and given in review of the widening
       itself; each now inherits ``get`` from
       :class:`~pcapkit.corekit.enum.EnumLookup` unchanged. ``LMAAddressCode`` and
       ``LocalizedRoutingStatus`` never carried a ``get`` at all, so they had no
       string lookup to fold. ``Criticality`` had one when this audit was taken and no
       longer does:
       :issue:`877` re-parented it onto
       :class:`~pcapkit.corekit.enum.EnumLookup` and :issue:`923` retired the exception
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
     - All 14 are pcapkit's own discriminators and bit labels, with no registrar behind
       them at all -- ``Completion``, ``ftp.Type``, ``httpv1.Type``, ``FinalisedState``,
       ``ESPStatus``, ``PacketDirection``, ``PacketReception``, and the 7 httpv2
       ``Flags``.
     - **case-sensitive** -- nothing to cite, nothing to change

Two rows the audit deliberately left open rather than acting on, because each is
wider than a case fix:

* **A service-name lookup on the** ``AppType`` **transport registries.** This is the
  inverse of every other row: :rfc:`6335#section-5.1` *does* make service names
  case-insensitive, and ``TCP``/``UDP``/``SCTP``/``DCCP`` take their member names from
  that column -- but ``AppType.get`` refuses a non-:class:`int` key, so no service-name
  lookup exists for the rule to apply to. Implementing one is new public API on a
  6,000-member registry where one name maps to many ports, which is a ``get_all``
  design question rather than a case fold.
* ``CommandType`` **and** ``ConformanceRequirement``. By parity with
  ``TransportProtocol`` -- an :class:`int`-valued enumeration whose *names* are the
  specification's own tokens -- the measured spelling disagreement above would make
  these two case-insensitive. Nothing looks them up by string today, though: the
  crawler translates the CSV's lower-case letters to the upper-case member names at
  generation time. Both classes inherit
  :class:`~pcapkit.corekit.enum.EnumLookup`, since
  :issue:`930` completed phase 2's
  re-parenting, so a ``get`` exists on each, case-sensitive like the
  base's own. Whether to fold case to match ``TransportProtocol``'s own override is a
  design question for whoever writes the first string-keyed caller, not one this
  audit settles.

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
   fall through to a value lookup, so an ``aenum.StrEnum`` registry would stop
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
   :issue:`903` that class overrides
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
   deliberately, since :rfc:`959#section-5` treats FTP command codes identically
   regardless of case. ``Method.get`` used to fold case the same way, but
   :issue:`896` made it
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

