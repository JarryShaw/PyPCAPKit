STP - Spanning Tree Protocol
==================================

.. module:: pcapkit.protocols.application.stp
.. module:: pcapkit.protocols.application.stp.protocol

:mod:`pcapkit.protocols.application.stp.protocol` holds
:class:`~pcapkit.protocols.application.stp.protocol.STP`, the abstract base of the
Spanning Tree Protocol family [*]_, whose Bridge Protocol Data Units (BPDUs) are
told apart by their Protocol Version Identifier. Each version is a member of its
own:

.. list-table::
   :header-rows: 1

   * - Version
     - Class
     - Specification
     - BPDUs
   * - 0
     - :class:`~pcapkit.protocols.application.stpv0.protocol.STPv0`
     - :ieee:`802.1D-2004` clause 9
     - Configuration, 35 octets, and Topology Change Notification (TCN), 4 octets
   * - 2
     - :class:`~pcapkit.protocols.application.rstp.protocol.RSTP`
     - :ieee:`802.1Q-2022` clause 14
     - RST, 36 octets
   * - 3
     - :class:`~pcapkit.protocols.application.mstp.protocol.MSTP`
     - :ieee:`802.1Q-2022` clause 14
     - MST, 102 octets and an MSTI Configuration Message of 16 for each MSTI

The members share the first four octets alone, the Protocol Identifier, the Protocol
Version Identifier and the BPDU Type, so the base parses no BPDU. LLC address
``0x42`` is the family's, as DSAP and SSAP both, so
:attr:`LLC.__proto__ <pcapkit.protocols.link.llc.protocol.LLC.__proto__>` binds this
base, paired, and it picks the member as :ieee:`802.1Q-2022` clause 14.4 validates a
BPDU, by :meth:`_classify`. A BPDU that clause discards is left
:class:`~pcapkit.protocols.misc.raw.protocol.Raw` behind LLC, and a direct parse of it
raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`; so is an SPT BPDU, of
version 4, which the family does not dissect.

The bridge's control plane computes the active topology rather than relaying
frames, so the family is a *user* of the stack, as a routing protocol is
(:doc:`/contributing/conventions/protocol-layer-placement`). The proprietary
per-VLAN variants, which no public specification defines, are not dissected.


.. versionadded:: 1.9.0

.. autoclass:: pcapkit.protocols.application.stp.protocol.STP
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: version
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
   .. automethod:: _classify
   .. automethod:: _is_mst
   .. automethod:: _construction_member
   .. automethod:: _rebuilt_version
   .. automethod:: _check_bpdu
   .. automethod:: _read_bridge_id
   .. automethod:: _make_bridge_id
   .. automethod:: _read_port_id
   .. automethod:: _make_port_id
   .. automethod:: _read_flags
   .. automethod:: _make_flags
   .. automethod:: _make_role_flags
   .. automethod:: _read_timer
   .. automethod:: _make_timer
   .. automethod:: _make_protocol_version

Data Models
-----------

.. module:: pcapkit.protocols.application.stp.data

.. autoclass:: pcapkit.protocols.application.stp.data.BridgeID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.stp.data.PortID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.stp.data.Flags
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Spanning_Tree_Protocol
