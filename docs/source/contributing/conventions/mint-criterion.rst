.. _mint-criterion:

Minting an Unrecognised Value
-----------------------------

Nearly every registry under :mod:`pcapkit.const` resolves an unrecognised value through
a ``_missing_`` override, which decides what happens when a value has no member. Only
:class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` and
:class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel` have none anywhere in their
MRO, so they carry no declared-but-unassigned range to resolve. The rest define one
themselves, except the transport subclasses of
:class:`~pcapkit.const.reg.apptype.apptype.AppType`, which inherit
:meth:`AppType._missing_ <pcapkit.const.reg.apptype.apptype.AppType._missing_>`
(:file:`pcapkit/const/reg/apptype/apptype.py`). The behaviours below follow from it, and
which one a given range gets is a **design decision, not a style preference**:

``extend_enum(cls, name, value)`` -- *mint*
   Creates a real, permanent member on the class. It is installed in
   ``_member_map_`` and ``_value2member_map_``, so it is visible to iteration,
   lookup and ``__members__`` from then on, for the life of the process.

:meth:`~pcapkit.corekit.enum.EnumRegistry._unregistered_member` -- *unmint*
   Returns a member-like object for the value **without** installing it. The registry
   does not grow, and a second lookup of the same value builds an equal but distinct
   object rather than handing back the first.

``super()._missing_(value)`` -- *hand back to* |aenum|_
   Neither of the above. For an |aenum|_ flag base this composes a pseudo-member and
   caches it in ``_value2member_map_`` only, so ``__members__`` and iteration are
   unchanged but a second lookup returns the same object. For a plain enum it
   returns ``None`` and the lookup raises :exc:`ValueError`; the measured case is
   an in-range hole in an unmint registry, ``BlockType(11)``.

Measured against the tree, by class:

* **Mints**: :class:`~pcapkit.const.mh.cga_type.CGAType` alone, whose values are 128-bit
  CGA extension tags rather than an IANA-style range of codes.
* **Unmint**: the bulk of the registries. The transport subclasses
  (:class:`~pcapkit.const.reg.apptype.tcp.TCP`,
  :class:`~pcapkit.const.reg.apptype.udp.UDP`,
  :class:`~pcapkit.const.reg.apptype.sctp.SCTP`,
  :class:`~pcapkit.const.reg.apptype.dccp.DCCP`) inherit the method; every other registry
  here calls ``_unregistered_member`` itself, though
  :class:`~pcapkit.const.reg.apptype.apptype.AppType` never gets there: it holds no
  members and raises for every value through its ``cls.__registry__ is None`` guard.

  **Some of the rest can never reach the call either**, because every range they declare is
  already covered by their own members -- :class:`~pcapkit.const.ipv4.tos_del.ToSDelay`
  declares ``0..1`` and has members ``[0, 1]``, so its ``_unregistered_member`` call is
  dead code. They are :mod:`ipv4.option_class <pcapkit.const.ipv4.option_class>`,
  :mod:`ipv4.tos_del <pcapkit.const.ipv4.tos_del>`,
  :mod:`ipv4.tos_ecn <pcapkit.const.ipv4.tos_ecn>`,
  :mod:`ipv4.tos_pre <pcapkit.const.ipv4.tos_pre>`,
  :mod:`ipv4.tos_rel <pcapkit.const.ipv4.tos_rel>`,
  :mod:`ipv4.tos_thr <pcapkit.const.ipv4.tos_thr>`,
  :mod:`ipv6.option_action <pcapkit.const.ipv6.option_action>`,
  :mod:`ipv6.seed_id <pcapkit.const.ipv6.seed_id>`,
  :mod:`ipv6.smf_dpd_mode <pcapkit.const.ipv6.smf_dpd_mode>`,
  :mod:`l2tp.type <pcapkit.const.l2tp.type>`,
  :mod:`mh.dhcp_support_mode <pcapkit.const.mh.dhcp_support_mode>` and
  :mod:`vlan.priority_level <pcapkit.const.vlan.priority_level>`.
* **Cache in the value table only**: :class:`~pcapkit.const.tcp.flags.Flags`,
  :class:`~pcapkit.const.ftp.command.CommandType` and the Mobility Header flag
  registries, such as :class:`~pcapkit.const.mh.binding_ack_flag.BindingACKFlag`. They
  range-check and hand back to ``super()._missing_``, which for an ``aenum.IntFlag``
  reaches ``_create_pseudo_member_`` and ends in
  ``cls._value2member_map_.setdefault(value, pseudo_member)``.
* **Raise for any unknown value**: :class:`~pcapkit.const.reg.apptype.apptype.AppType`,
  :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader`,
  :class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel` and
  :class:`~pcapkit.const.hip.transport.Transport`.
  :class:`~pcapkit.const.hip.transport.Transport` raises from its own range check: its
  declared range ``0..3`` is exactly its member set, so no unassigned value is left for
  ``super()._missing_`` (the line after the check is unreachable).

Note that these are |aenum|_ classes: ``issubclass(Flags, enum.IntFlag)`` is ``False``
against the standard library and ``True`` against ``aenum.IntFlag``, so a probe against
``enum`` answers about the wrong hierarchy.

The mint criterion below therefore applies only to the registries that unmint, where it
decides the *name* an unregistered member carries -- the registrar's own label suffixed
with the individual code, or the bare block label on its own -- not whether it
registers. In the others it never runs: :class:`~pcapkit.const.mh.cga_type.CGAType` names
its tag from the value, the flag registries compose a name from their members' bits, and
those that raise name nothing. The crawlers that generate the ranges record that narrowing
in their own comments: :file:`pcapkit/vendor/reg/ethertype.py`'s ``UNASSIGNED_ROW_NAMES``
and :file:`pcapkit/vendor/ipx/socket.py`'s ``UNASSIGNED_RANGE_NAMES``.

.. mermaid::

   ---
   config:
     flowchart:
       curve: monotoneX
   ---
   flowchart LR
       LOOKUP["cls(value) finds no member"] --> MISSING["\_missing\_"]
       MISSING -->|"out of range, or no block covers it"| RAISE["ValueError"]
       MISSING -->|"CGAType only"| MINT["extend_enum<br/>permanent member, registry grows"]
       MISSING -->|"flag registries"| FLAG["super().\_missing\_<br/>pseudo-member cached in the value table only"]
       MISSING -->|"block label names a party"| SUFFIXED["_unregistered_member<br/>label + _0x&lt;code&gt;"]
       MISSING -->|"block label names a procedure"| BARE["_unregistered_member<br/>bare block label"]

The Criterion
~~~~~~~~~~~~~

The test, paraphrased from the maintainer's ruling: does the upstream registry treat
the label as the final, concrete assigned name, or only as a notation for a human
reading the table?

Settled in review of the
:meth:`Socket._missing_ <pcapkit.const.ipx.socket.Socket._missing_>` branch-order fix
(:issue:`841`) and reaffirmed on :issue:`775` as a core concept of the ruling.

So the question to ask of a range is **what the upstream registry actually did**, not
what the generated code happens to look like:

*  The source assigns a **real, specific name** to those codes. The name records
   something the registry genuinely says, so it is carried across and suffixed with the
   code it belongs to.
*  The source says only that the codes are spoken for, without naming them --
   ``Unassigned``, ``Reserved``, ``Reserved for Private Use``,
   ``Reserved for Experimental Use``, ``Deprecated``, ``Dynamically Assigned``
   and ``Statically Assigned``. These are written for a human reading the table, so the
   bare label stands: suffixing one with a code would **manufacture a name nobody
   assigned**, and the value will get its real name if and when something assigns it.

.. note::

   In the transport registries -- :class:`~pcapkit.const.reg.apptype.tcp.TCP`,
   :class:`~pcapkit.const.reg.apptype.udp.UDP` and the rest -- the spans IANA assigns
   to a service are an exception to the first case: ``x11``, ``ircu``, ``swx`` and the
   others resolve with the bare service name, so ``TCP(6001).name`` is ``'x11'``, not
   ``'x11_6001'``. Suffixing them would change ``.name``, which a caller can observe.
   Recorded on :issue:`2550`.

Worked Examples
~~~~~~~~~~~~~~~

*Bare label.* :mod:`pcapkit.const.ipx.socket`'s ``Dynamically Assigned``,
``Dynamically Assigned Socket Numbers``, ``Statically Assigned Socket Numbers`` and
``Experimental`` ranges. Each names **how the socket will be allocated**, not what
occupies it; the real name arrives with the allocation.

*Suffixed.* :mod:`pcapkit.const.reg.ethertype`'s company names -- ``Xyplex``,
``Datability``, ``Qualcomm``, ``Motorola`` and many others, some of them holding more
than one range block -- and
:mod:`pcapkit.const.ipx.socket`'s ``Registered by Xerox``. A company name is the
assignment, for the reason in the next section.

Further ranges in :mod:`pcapkit.const.reg.ethertype` carry a suffixed name without
being company names at all: ``IEEE802.3 Length Field``, which names a field in a standard, and
``Berkeley Trailer encap/IP``, which names an encapsulation. Neither is among the company names, and
neither is suffixed for the reason the next section gives.

.. note::

   Those two groups look alike and the line between them is **not** range-versus-single
   code. ``Registered by Xerox`` covers a range and is still suffixed per socket,
   because it names *who registered the socket*. ``Dynamically Assigned`` also covers a
   range and is not, because it names only the *mechanism* by which some future party
   will take it. Ask what the label tells you: a party, or a procedure.

Suffixed Company Names
~~~~~~~~~~~~~~~~~~~~~~

The ethertype case looks like an exception to the rule and is not. The maintainer's
reasoning, settled on :issue:`775` after
being raised in review of the same
:meth:`Socket._missing_ <pcapkit.const.ipx.socket.Socket._missing_>` fix (:issue:`841`): a
proprietary protocol will never have a public name, so the company name is what serves
that purpose in its place.

So the company name is not a note *about* the code -- it is the best name that will ever
exist *for* it, which makes it the final concrete assigned name under the test above.
That is also why ``DEC Unassigned`` goes the other way despite carrying the same
attribution: there the company holds the block and assigned nothing, so the notation is
"Unassigned" and the attribution is incidental.

Checking the Current State
~~~~~~~~~~~~~~~~~~~~~~~~~~

The split is measurable rather than a matter of memory. Slice each ``_missing_`` body
and see which call it makes -- an :mod:`ast` walk is reliable where a text search is
not, because ``extend_enum`` also appears in imports and in prose. Match on the
attribute name as well as on the bare name: ``extend_enum`` is called as a plain
function, but ``_unregistered_member`` is called on ``cls``, so a walk that inspects
only ``ast.Name`` nodes finds every mint and no unmint at all:

.. code-block:: python

   import ast, pathlib

   for path in sorted(pathlib.Path('pcapkit/const').rglob('*.py')):
       if path.name == '__init__.py':
           continue
       tree = ast.parse(path.read_text())
       for node in ast.walk(tree):
           if isinstance(node, ast.FunctionDef) and node.name == '_missing_':
               calls = {n.func.id if isinstance(n.func, ast.Name) else n.func.attr
                        for n in ast.walk(node) if isinstance(n, ast.Call)
                        and isinstance(n.func, (ast.Name, ast.Attribute))}
               if 'extend_enum' in calls:
                   print('MINT  ', path)
               elif '_unregistered_member' in calls:
                   print('UNMINT', path)

.. note::

   The walk reads each file's own ``_missing_``, so it reports
   :class:`~pcapkit.const.reg.apptype.apptype.AppType` as an unmint although it raises,
   prints nothing for the flag registries and
   :class:`~pcapkit.const.hip.transport.Transport` (they call neither function) nor for
   :class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader` and
   :class:`~pcapkit.const.pcapng.tls_key_label.TLSKeyLabel` (they define no
   ``_missing_``), and does not see the transport subclasses, which inherit theirs.
   :class:`~pcapkit.const.ftp.command.CommandType` is one of those flag registries, and
   the ``UNMINT`` lines for :file:`pcapkit/const/ftp/command.py` are the file's other
   registries. Reconcile it against a runtime probe for the split in the list above.

.. warning::

   Calling ``Cls(value)`` on a registry that mints or hands back to a flag base
   **mutates the class**. A probe is not a read: it installs something that every later
   lookup then finds. :class:`~pcapkit.const.mh.cga_type.CGAType`
   grows ``__members__``, ``_member_map_`` and ``_value2member_map_``;
   :class:`~pcapkit.const.tcp.flags.Flags`,
   :class:`~pcapkit.const.ftp.command.CommandType` and the Mobility Header flag
   registries grow ``_value2member_map_`` only. Snapshot
   ``{member.value for member in Cls}`` before any lookup regardless -- that snapshot
   cannot see the flag registries' cache, so compare ``len(Cls._value2member_map_)``
   too -- and use a throwaway process per registry when comparing behaviour across
   revisions.
