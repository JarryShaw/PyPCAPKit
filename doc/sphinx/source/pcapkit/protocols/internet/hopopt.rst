HOPOPT - IPv6 Hop-by-Hop Options
================================

.. module:: pcapkit.protocols.internet.hopopt
.. module:: pcapkit.protocols.data.internet.hopopt

:mod:`pcapkit.protocols.internet.hopopt` contains
:class:`~pcapkit.protocols.internet.hopopt.HOPOPT`
only, which implements extractor for IPv6 Hop-by-Hop
Options header (HOPOPT) [*]_, whose structure is
described as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``hopopt.next``             Next Header
  1           8   ``hopopt.length``           Header Extensive Length
  2          16   ``hopopt.options``          Options
======= ========= =================== =================================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.internet.hopopt.HOPOPT
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_option

   .. automethod:: _read_opt_type
   .. automethod:: _read_hopopt_options

   .. automethod:: _read_opt_none
   .. automethod:: _read_opt_pad
   .. automethod:: _read_opt_tun
   .. automethod:: _read_opt_ra
   .. automethod:: _read_opt_calipso
   .. automethod:: _read_opt_smf_dpd
   .. automethod:: _read_opt_pdm
   .. automethod:: _read_opt_qs
   .. automethod:: _read_opt_rpl
   .. automethod:: _read_opt_mpl
   .. automethod:: _read_opt_ilnp
   .. automethod:: _read_opt_lio
   .. automethod:: _read_opt_jumbo
   .. automethod:: _read_opt_home
   .. automethod:: _read_opt_ip_dff

   .. autoattribute:: __option__
      :no-value:

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.internet.hopopt.HOPOPT(next, length, options)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: next
   .. autoattribute:: length
   .. autoattribute:: options

.. autoclass:: pcapkit.protocols.data.internet.hopopt.Option(type, action, change, length)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: type
   .. autoattribute:: action
   .. autoattribute:: change
   .. autoattribute:: length

.. autoclass:: pcapkit.protocols.data.internet.hopopt.UnassignedOption(type, action, change, length, data)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data

.. autoclass:: pcapkit.protocols.data.internet.hopopt.PadOption(type, action, change, length)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.internet.hopopt.TunnelEncapsulationLimitOption(type, action, change, length, limit)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: limit

.. autoclass:: pcapkit.protocols.data.internet.hopopt.RouterAlertOption(type, action, change, length, value)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: value

.. autoclass:: pcapkit.protocols.data.internet.hopopt.CALIPSOOption(type, action, change, length, domain, cmpt_len, level, checksum)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: domain
   .. autoattribute:: cmpt_len
   .. autoattribute:: level
   .. autoattribute:: checksum
   .. autoattribute:: cmpt_bitmap

.. autoclass:: pcapkit.protocols.data.internet.hopopt.SMFDPDOption(type, action, change, length, dpd_type, tid_type)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: dpd_type
   .. autoattribute:: tid_type

.. autoclass:: pcapkit.protocols.data.internet.hopopt.SMFIdentificationBasedDPDOption(type, action, change, length, pdm_type, tid_type, tid_len, tid, id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: tid_len
   .. autoattribute:: tid
   .. autoattribute:: id

.. autoclass:: pcapkit.protocols.data.internet.hopopt.SMFHashBasedDPDOption(type, action, change, length, pdm_type, tid_type, hav)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hav

.. autoclass:: pcapkit.protocols.data.internet.hopopt.PDMOption(type, action, change, length, scaledtlr, scaledtls, psntp, psnlr, deltatlr, deltatls)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: scaledtlr
   .. autoattribute:: scaledtls
   .. autoattribute:: psntp
   .. autoattribute:: psnlr
   .. autoattribute:: deltatlr
   .. autoattribute:: deltatls

.. autoclass:: pcapkit.protocols.data.internet.hopopt.QuickStartOption(type, action, change, length, func, rate, ttl, nounce)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: func
   .. autoattribute:: rate
   .. autoattribute:: ttl
   .. autoattribute:: nounce

.. autoclass:: pcapkit.protocols.data.internet.hopopt.RPLOption(type, action, change, length, flags, id, rank)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: flags
   .. autoattribute:: id
   .. autoattribute:: rank

.. autoclass:: pcapkit.protocols.data.internet.hopopt.RPLFlags(down, rank_err, fwd_err)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: down
   .. autoattribute:: rank_err
   .. autoattribute:: fwd_err

.. autoclass:: pcapkit.protocols.data.internet.hopopt.MPLOption(type, action, change, length, seed_type, flags, seq, seed_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: seed_type
   .. autoattribute:: flags
   .. autoattribute:: seq
   .. autoattribute:: seed_id

.. autoclass:: pcapkit.protocols.data.internet.hopopt.MPLFlags(max, verification)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: max
   .. autoattribute:: verification

.. autoclass:: pcapkit.protocols.data.internet.hopopt.ILNPOption(type, action, change, length, nounce)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: nounce

.. autoclass:: pcapkit.protocols.data.internet.hopopt.LineIdentificationOption(type, action, change, length, line_id_len, line_id)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: line_id_len
   .. autoattribute:: line_id

.. autoclass:: pcapkit.protocols.data.internet.hopopt.JumboPayloadOption(type, action, change, length, payload_len)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: payload_len

.. autoclass:: pcapkit.protocols.data.internet.hopopt.HomeAddressOption(type, action, change, length, address)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: address

.. autoclass:: pcapkit.protocols.data.internet.hopopt.IPDFFOption(type, action, change, length, version, flags, seq)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: version
   .. autoattribute:: flags
   .. autoattribute:: seq

.. autoclass:: pcapkit.protocols.data.internet.hopopt.DFFFlags(dup, ret)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: dup
   .. autoattribute:: ret

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options
