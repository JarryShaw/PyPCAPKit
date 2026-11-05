Netlink - Linux Netlink Socket Framing
=======================================

.. module:: pcapkit.protocols.link.netlink
.. module:: pcapkit.protocols.link.netlink.protocol

:mod:`pcapkit.protocols.link.netlink.protocol` contains
:class:`~pcapkit.protocols.link.netlink.protocol.Netlink`
only, which implements the extractor for the ``struct nlmsghdr`` framing of
Linux's own kernel/user IPC transport, as seen on a
``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type``
is ``ARPHRD_NETLINK`` (an ``nlmon`` interface). Its structure is:

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

Only the first message's fixed 16-octet header is dissected. The rest of the
frame -- that message's per-family payload and any further messages -- is its
payload, kept as :class:`~pcapkit.protocols.misc.raw.protocol.Raw` unless the
``nlmsg_type`` is registered. The header is in the capturing host's byte order,
which nothing records (Netlink [*]_ is kernel/userspace IPC, not a wire format),
so :func:`nlmsg_byteorder` guesses it; either way it is kept as
``netlink.byteorder``.

.. versionadded:: 1.6.0

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
