OSPF - Open Shortest Path First
===============================

.. module:: pcapkit.protocols.application.ospf
.. module:: pcapkit.protocols.application.ospf.protocol

:mod:`pcapkit.protocols.application.ospf.protocol` contains
:class:`~pcapkit.protocols.application.ospf.protocol.OSPF` only, the abstract base of
the Open Shortest Path First (OSPF) family [*]_. Each version is a member of its own:

.. list-table::
   :header-rows: 1

   * - Version
     - Class
     - Specification
     - Header
   * - 1
     - :class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1`
     - :rfc:`1131`
     - 24 octets, AuType and Authentication
   * - 2
     - :class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2`
     - :rfc:`2328`
     - 24 octets, AuType and Authentication
   * - 3
     - :class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3`
     - :rfc:`5340`
     - 16 octets, Instance ID and a reserved octet

All three share the first 14 octets alone, Version to Checksum, so the base
parses no header. IP protocol 89 is OSPF's in every version, so
:attr:`Internet.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`
binds this base, which picks the member by the Version octet. Each RFC requires its
own version there (:rfc:`1131` Section 8.2, :rfc:`2328#section-8.2`,
:rfc:`5340#section-4.2.2`), so a direct parse of any other version raises
:exc:`~pcapkit.utilities.exceptions.ProtocolError`, and behind IP the packet is left
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

.. versionadded:: 1.5.0

   Moved here from ``pcapkit.protocols.link.ospf``, with its data model and
   header schema. :class:`~pcapkit.protocols.application.ospf.protocol.OSPF` derives
   from :class:`~pcapkit.protocols.application.application.Application`, so
   its layer is ``'Application'`` (:issue:`719`).

.. versionremoved:: 1.5.0

   ``pcapkit.protocols.link.ospf``, ``pcapkit.protocols.data.link.ospf`` and
   ``pcapkit.protocols.schema.link.ospf``, the ``OSPF`` name that
   :mod:`pcapkit.protocols.link`, ``pcapkit.protocols.data.link`` and
   ``pcapkit.protocols.schema.link`` each exported, and the
   ``OSPF_CrytographicAuthentication`` name that
   ``pcapkit.protocols.data.link`` and ``pcapkit.protocols.schema.link``
   exported, with no alias (:issue:`719`, :issue:`1090`).

.. versionchanged:: 1.5.0

   A rebuild keeps the parsed Packet Length and the octets past it, where
   ``OSPF.make`` recomputed the length from the payload and dropped those octets;
   it takes them as ``packet_length`` and ``trailer`` (:issue:`1249`,
   :issue:`1455`).

.. versionchanged:: 1.8.1

   :class:`~pcapkit.protocols.application.ospf.protocol.OSPF` became the abstract base
   of the family, giving :class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1`,
   :class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2` or
   :class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3`; it read every
   version with OSPFv2's 24-octet header, OSPFv3's 16-octet one included. A version
   none of them reads, 0 or 4 to 255, is refused, and left
   :class:`~pcapkit.protocols.misc.raw.protocol.Raw` behind IP (:issue:`3105`).

.. versionremoved:: 1.8.1

   ``pcapkit.protocols.application.ospf.schema`` and
   ``pcapkit.protocols.application.ospf.data``, with their ``OSPF`` and
   ``CryptographicAuthentication`` classes and
   ``pcapkit.protocols.application.ospf.schema.ospf_auth_data_selector``;
   ``pcapkit.protocols.application.ospf.Schema_OSPF``,
   ``pcapkit.protocols.application.ospf.Schema_CryptographicAuthentication``,
   ``pcapkit.protocols.application.ospf.Data_OSPF`` and
   ``pcapkit.protocols.application.ospf.Data_CryptographicAuthentication``; and
   ``OSPF.read``, ``OSPF.make`` and ``OSPF.length``, with ``OSPF._make_data``,
   ``OSPF._read_encrypt_auth``, ``OSPF._make_encrypt_auth``, ``OSPF._read_id_numbers``
   and ``OSPF._make_id_numbers``. None has an alias: the OSPFv2 header moved to
   :mod:`pcapkit.protocols.application.ospfv2`, as ``OSPFv2``, and each member defines
   its own ``read``, ``make`` and ``length`` (:issue:`3105`).

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.ospf.protocol.OSPF
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: info_name
   .. autoproperty:: type

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: from_data

   .. rubric:: Data Models

   .. automethod:: __index__
   .. automethod:: __length_hint__
   .. automethod:: __init__
   .. automethod:: __new__

   .. rubric:: Utilities

   .. automethod:: _member_of_version
   .. automethod:: _dispatch
   .. automethod:: _construction_member
   .. automethod:: _make_version
   .. automethod:: _rebuilt_version
   .. automethod:: _verify_checksum
   .. automethod:: _compute_checksum

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Open_Shortest_Path_First
