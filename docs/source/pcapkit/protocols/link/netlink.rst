Netlink - Linux Netlink Socket Framing
=======================================

.. module:: pcapkit.protocols.link.netlink
.. module:: pcapkit.protocols.link.netlink.protocol

:mod:`pcapkit.protocols.link.netlink.protocol` contains
:class:`~pcapkit.protocols.link.netlink.protocol.Netlink`
only, which implements the extractor for the ``struct nlmsghdr`` framing of
Linux's own kernel/user IPC transport, as seen on a
``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type``
is ``ARPHRD_NETLINK`` (an ``nlmon`` interface). Its structure is described as
below:

.. table::

   ====== ==== ======================= ================================
   Octets Bits Name                    Description
   ====== ==== ======================= ================================
   0      0    ``netlink.nlmsg_len``   Message Length (header included)
   4      32   ``netlink.nlmsg_type``  Message Type
   6      48   ``netlink.nlmsg_flags`` Message Flags
   8      64   ``netlink.nlmsg_seq``   Sequence Number
   12     96   ``netlink.nlmsg_pid``   Sender Port ID
   ====== ==== ======================= ================================

Only this fixed 16-octet header is dissected; per-family message payloads and
multiple messages packed into one capture are out of scope for this first
cut -- see the module docstring's *Scope* section. The byte order the header
was written in is ambiguous (Netlink [*]_ is kernel/userspace IPC, not wire
format) and is guessed by :func:`nlmsg_byteorder`; either way it is kept as
``netlink.byteorder``.

.. autoclass:: pcapkit.protocols.link.netlink.protocol.Netlink
   :no-members:
   :show-inheritance:

   .. autoattribute:: __proto__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make
   .. automethod:: register

   .. automethod:: __length_hint__
   .. automethod:: __index__

   .. automethod:: _make_data

.. autofunction:: pcapkit.protocols.link.netlink.protocol.nlmsg_byteorder

Header Schemas
--------------

.. module:: pcapkit.protocols.link.netlink.schema

.. autoclass:: pcapkit.protocols.link.netlink.schema.Netlink
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.link.netlink.data

.. autoclass:: pcapkit.protocols.link.netlink.data.Netlink
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] :manpage:`netlink(7)`; :rfc:`3549#section-2.3.2`
