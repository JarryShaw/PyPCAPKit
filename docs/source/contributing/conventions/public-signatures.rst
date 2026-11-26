.. _public-signatures:

Public Signatures
-----------------

How a public callable takes its arguments: the functions of :mod:`pcapkit.interface`,
the public classes of :mod:`pcapkit.foundation`, and
:class:`~pcapkit.protocols.protocol.Protocol` and its subclasses. Ruled by the owner on
:issue:`2834`, over one configuration object held in a context variable, which would
move each call's contract out of its signature. A public signature that breaks a rule
here is brought into line by a change of its own.

The Rules
~~~~~~~~~

#. **The primary input stays positional, and everything after it is keyword-only**, so
   adding a parameter moves no other.
#. **One name per concept.** ``layer``, ``protocol``, ``context``, ``strict`` and
   ``store`` mean the same wherever they appear. A format is ``format``, never
   ``fmt``; ``timeout`` is a number of seconds, never a flag; a callback is added by
   ``register_callback(callback, *, index=None)``, under no second name; and
   ``analyze`` is the one spelling, for a keyword as for a method.
#. **A wrapper mirrors the signature of what it wraps** -- a :mod:`pcapkit.interface`
   function that of the class it builds, and a :mod:`pcapkit.foundation.registry`
   function that of the classmethod it calls (:ref:`registry-protocol`) -- and a test
   pins the two equal.
#. **A real default is written in the signature.** :obj:`None` means off, never a
   default chosen out of sight.
#. **A keyword set is closed.** An unknown keyword is refused, never accepted and
   ignored.

Feature Options
~~~~~~~~~~~~~~~

**A feature's options are grouped in a** ``*Options`` **class**, whose fields take the
keyword names of the class the feature configures. The feature's own keyword takes:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Value
     - Means
   * - :obj:`None` or ``[]``
     - the feature is off
   * - a list of registered names
     - shorthand for the options object naming them, its other fields at their
       defaults
   * - the options object
     - the feature is on, as the object configures it

So an option for a feature that is off cannot be passed at all, rather than being
silently ignored. ``[]`` meaning off was ruled in review of :pr:`2868`
(:issue:`2836`), and so were these:

*  The ``*Options`` classes are exported from :mod:`pcapkit.interface`, and so from
   :mod:`pcapkit`, beside the functions that take them.
*  A field with no real default, such as the output file or the protocol names, stays
   required rather than gaining a guessed one.
*  An unknown name, for ``layer`` as for a format or a protocol, raises
   :exc:`~pcapkit.utilities.exceptions.FormatError`, and a feature keyword of the
   wrong type raises :exc:`~pcapkit.utilities.exceptions.RegistryError`, a
   :exc:`TypeError`.

**A** ``PCAPKIT_*`` **tunable is a process-wide limit or policy; an option is per
call.** A setting a caller varies from one call to the next is a keyword, and one that
bounds the whole process, as :data:`~pcapkit.utilities.config.TCP_GAP_LIMIT` does, is
a :mod:`pcapkit.utilities.config` tunable. The ``Options`` suffix keeps the classes
from reading as those tunables.

Protocols
~~~~~~~~~

**Calling a protocol class with a file parses, and with keywords alone builds**, ruled
on :issue:`3081` over the parse-only call of :issue:`2840`. Each shape has an explicit
form, :meth:`~pcapkit.protocols.protocol.Protocol.parse` and
:meth:`~pcapkit.protocols.protocol.Protocol.build`, named on :issue:`3081` as a verb to
pair with ``parse``:

.. code-block:: python

   Proto(file, length=None, /, *, layer=None, protocol=None, context=None)
   Proto(*, context=None, **fields)
   Proto.parse(file, length=None, /, *, layer=None, protocol=None, context=None)
   Proto.build(*, context=None, **fields)

*  ``length`` is positional beside ``file``, as :issue:`2834` specified for the
   protocols: the one exception to rule 1, since it bounds the input rather than
   configuring the call.
*  A parse takes no field and a construction no stop, so each keyword set is
   closed. Given no file, ``layer`` and ``protocol`` are fields where the class
   takes one of that name, as
   :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`,
   :class:`~pcapkit.protocols.link.ppp.protocol.PPP` and
   :class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo` take
   ``protocol``, and are refused otherwise, as ``length`` is. A keyword is
   always a keyword: ``file=`` and ``length=`` are fields too, never the
   positional parameters of their names (:issue:`3081`). Each shape is an
   overload, so a type checker reads ``protocol`` there as the field on a
   construction and as the stop on a parse.
*  ``layer`` is a layer name and ``protocol`` a protocol name, class or instance,
   and :obj:`None` is the only no stop, by rule 4.
*  A parse that needs an input of its own takes it keyword-only, before the stops:

   .. list-table::
      :header-rows: 1
      :widths: 50 50

      * - Class, and the classes deriving from it
        - Keywords
      * - :class:`~pcapkit.protocols.internet.ip.protocol.IP`,
          :class:`~pcapkit.protocols.internet.icmp.protocol.ICMP`,
          :class:`~pcapkit.protocols.internet.igmp.protocol.IGMP`,
          :class:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL`,
          :class:`~pcapkit.protocols.application.http.protocol.HTTP`,
          :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP`
        - ``version``, which names the member and must be the class's own
          (:ref:`protocol-family-dispatch`)
      * - :class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame`
        - ``num``, ``header``
      * - :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`
        - ``num``, ``sct``, ``ctx``
      * - :class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext`
        - ``extension``
      * - :class:`~pcapkit.protocols.application.dns.protocol.DNS`
        - ``framed``
      * - :class:`~pcapkit.protocols.link.loopback.protocol.Loopback`,
          :class:`~pcapkit.protocols.link.netlink.protocol.Netlink`
        - ``byteorder``

   A construction takes each as a field where the class's hooks do, and ``version``
   names the member there too.
*  What a layer hands the layer it carries -- the code it dispatched on, its
   packet data, its IP version -- travels through one private channel,
   :meth:`~pcapkit.protocols.protocol.Protocol._from_parent`, to the hooks, never
   through a public signature.
*  :meth:`~pcapkit.protocols.protocol.Protocol.analyze`,
   :meth:`~pcapkit.protocols.transport.transport.Transport.analyze` and
   :meth:`~pcapkit.protocols.transport.sctp.protocol.SCTP.analyze` take the parse's
   keywords, by rule 3.

Each misuse raises a :exc:`TypeError`, or one of the library's errors where a value
rather than a keyword is wrong:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Misuse
     - Raises
   * - a field, or an unknown keyword, given a file
     - :exc:`TypeError`, naming each
   * - no octets, as ``Proto(None)``
     - :exc:`TypeError`, naming ``build``
   * - a stop that is no field, or a ``length``, given no file
     - :exc:`TypeError`, naming each
   * - a ``file`` or ``length`` keyword no field takes
     - :exc:`~pcapkit.utilities.exceptions.UnexpectedKeyword`, saying to pass
       them positionally to parse
   * - an unknown construction keyword
     - :exc:`~pcapkit.utilities.exceptions.UnexpectedKeyword`, a :exc:`TypeError`
       and an :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`
   * - a ``layer`` naming no layer
     - :exc:`~pcapkit.utilities.exceptions.FormatError`
   * - a ``protocol`` of no stop's type
     - :exc:`~pcapkit.utilities.exceptions.RegistryError`, a :exc:`TypeError`
   * - another member's ``version``
     - :exc:`~pcapkit.utilities.exceptions.ProtocolError`

Incompatible Changes
~~~~~~~~~~~~~~~~~~~~

**An incompatible signature change is made outright, with no shim.** A shim taking the
old keywords hides what the call accepts from its signature, which these rules exist to
show. :issue:`2594` set the precedent, for the keyword groups of ``make()``.

**No default flip keeps a shim either**, :func:`~pcapkit.interface.core.reassemble`'s
``strict`` included, over the one-release warning :issue:`2834` gave it. Ruled in review
of :pr:`2894` (:issue:`2837`).
