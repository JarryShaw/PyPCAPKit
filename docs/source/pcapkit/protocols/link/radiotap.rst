Radiotap - IEEE 802.11 Radiotap Header
========================================

.. module:: pcapkit.protocols.link.radiotap

:mod:`pcapkit.protocols.link.radiotap` contains
:class:`~pcapkit.protocols.link.radiotap.Radiotap`
only, which implements the extractor for the radiotap header [*]_ capture
tools prepend to an 802.11 frame, as seen on a
``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type``
is ``ARPHRD_IEEE80211_RADIOTAP``. Radiotap is not part of the 802.11
standard itself -- it is a prefix written by the capturing tool, in front of
the raw 802.11 MAC frame. Its fixed start, all little-endian, is described
as below:

.. table::

   ====== ==== ======================== ================================
   Octets Bits Name                     Description
   ====== ==== ======================== ================================
   0      0    ``radiotap.it_version``  Header Revision (always ``0``)
   1      8    ``radiotap.it_pad``      Padding
   2      16   ``radiotap.it_len``      Header Length (header included)
   4      32   ``radiotap.it_present``  First Present-Flags Word
   ====== ==== ======================== ================================

followed by a chain of further present-flags words -- bit 31 of a word
signals that another follows -- and then the optional-field region those
bitmasks select, each field aligned and sized per its own type. ``it_len``
bounds the whole of it; the 802.11 MAC frame starts at that offset.

Scope
-----

Decoding every optional field radiotap.org defines is tracked on
:issue:`2576`. This class:

* **Decodes** the fixed 8-octet start -- ``it_version``, ``it_pad``,
  ``it_len`` -- and walks the present-flags chain far enough to know how
  many words it has
  (:attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.present`), without
  decoding what any bit selects.
* **Skips, rather than decodes,** the optional-field region those bits
  select -- the octets between the present-flags chain and ``it_len`` are
  kept whole and undissected, as
  :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.fields`.
* **Hands** everything from ``it_len`` on, the 802.11 MAC frame, to
  :class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11`
  (:class:`~pcapkit.protocols.misc.null.NoPayload` when nothing follows).
  The header names no next protocol, since an 802.11 frame always follows it,
  so the frame is looked up in
  :attr:`Radiotap.__proto__ <pcapkit.protocols.link.radiotap.Radiotap.__proto__>`
  under :attr:`LinkType.IEEE802_11 <pcapkit.const.reg.linktype.LinkType.IEEE802_11>`;
  :func:`~pcapkit.foundation.registry.protocols.register_radiotap` replaces
  the entry.

.. autoclass:: pcapkit.protocols.link.radiotap.Radiotap
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register

   .. automethod:: __length_hint__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _get_payload

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.link.radiotap

.. autoclass:: pcapkit.protocols.schema.link.radiotap.Radiotap
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.link.radiotap

.. autoclass:: pcapkit.protocols.data.link.radiotap.Radiotap
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] <https://www.radiotap.org/>; the Linux kernel's
   ``include/net/ieee80211_radiotap.h`` and ``net/wireless/radiotap.c``; and
   Wireshark's ``packet-ieee80211-radiotap.c``.
