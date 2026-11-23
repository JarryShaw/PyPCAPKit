DNS - Domain Name System
========================

.. module:: pcapkit.protocols.application.dns
.. module:: pcapkit.protocols.application.dns.protocol

:mod:`pcapkit.protocols.application.dns.protocol` contains
:class:`~pcapkit.protocols.application.dns.protocol.DNS` only, which implements
an extractor for Domain Name System (DNS) messages [:rfc:`1035`], whose header
is:

.. table::

   ====== ===== ================== ===========================================
   Octets Bits  Name               Description
   ====== ===== ================== ===========================================
   0          0 ``dns.length``     Message Length (over TCP only)
   ------ ----- ------------------ -------------------------------------------
   0          0 ``dns.id``         Identifier
   ------ ----- ------------------ -------------------------------------------
   2         16 ``dns.flags``      QR, Opcode, AA, TC, RD, RA, Z, AD, CD, RCODE
   ------ ----- ------------------ -------------------------------------------
   4         32 ``dns.qdcount``    Question Count
   ------ ----- ------------------ -------------------------------------------
   6         48 ``dns.ancount``    Answer Count
   ------ ----- ------------------ -------------------------------------------
   8         64 ``dns.nscount``    Authority Count
   ------ ----- ------------------ -------------------------------------------
   10        80 ``dns.arcount``    Additional Count
   ====== ===== ================== ===========================================

Over TCP, the two-octet length precedes the message, so every offset above
moves two octets on (:rfc:`1035#section-4.2.2`, :rfc:`7766#section-8`).

How a parse reads a message:

.. mermaid::

   flowchart TD
       IN["octets at port 53"] --> GIVEN{"framed= given?"}
       GIVEN -->|yes| READ["read as it says"]
       GIVEN -->|no| WHOLE{"a whole message that fits<br/>behind a length field?"}
       WHOLE -->|no| UNFRAMED["one message, unframed"]
       WHOLE -->|yes| PLAIN{"do the sections the header<br/>counts fit the octets?"}
       PLAIN -->|no| FRAMED["one message, framed"]
       PLAIN -->|yes| EXACT{"does the framed one end<br/>exactly at its length?"}
       EXACT -->|no| UNFRAMED
       EXACT -->|yes| END{"does the plain one stop<br/>short of the end?"}
       END -->|yes| FRAMED
       END -->|no| TIE{"a question in the framed one only,<br/>or a further exact framed message?"}
       TIE -->|yes| FRAMED
       TIE -->|no| UNFRAMED
       FRAMED --> NEXT{"a whole framed message after it?"}
       NEXT -->|yes| CHAIN["a further DNS layer"]
       NEXT -->|no| REST["the rest as Raw"]

.. versionadded:: 1.7.0

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.dns.protocol.DNS
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __rdata__
      :no-value:
   .. autoattribute:: __option__
      :no-value:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: rcode

   .. rubric:: Methods

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register_option
   .. automethod:: register_rdata

   .. rubric:: Data Models

   .. automethod:: __index__
   .. automethod:: __post_init__

   .. rubric:: Utilities

   .. automethod:: _make_data
   .. automethod:: _read_dns_question
   .. automethod:: _make_dns_question
   .. automethod:: _read_dns_record
   .. automethod:: _make_dns_record

   .. automethod:: _read_rdata_unknown
   .. automethod:: _read_rdata_a
   .. automethod:: _read_rdata_ns
   .. automethod:: _read_rdata_cname
   .. automethod:: _read_rdata_soa
   .. automethod:: _read_rdata_ptr
   .. automethod:: _read_rdata_mx
   .. automethod:: _read_rdata_txt
   .. automethod:: _read_rdata_aaaa
   .. automethod:: _read_rdata_srv
   .. automethod:: _read_rdata_caa
   .. automethod:: _read_opt_unknown
   .. automethod:: _read_opt_client_subnet
   .. automethod:: _read_opt_cookie
   .. automethod:: _read_opt_tcp_keepalive
   .. automethod:: _read_opt_extended_error
   .. automethod:: _make_rdata_unknown
   .. automethod:: _make_rdata_a
   .. automethod:: _make_rdata_ns
   .. automethod:: _make_rdata_cname
   .. automethod:: _make_rdata_soa
   .. automethod:: _make_rdata_ptr
   .. automethod:: _make_rdata_mx
   .. automethod:: _make_rdata_txt
   .. automethod:: _make_rdata_aaaa
   .. automethod:: _make_rdata_srv
   .. automethod:: _make_rdata_caa
   .. automethod:: _make_opt_unknown
   .. automethod:: _make_opt_client_subnet
   .. automethod:: _make_opt_cookie
   .. automethod:: _make_opt_tcp_keepalive
   .. automethod:: _make_opt_extended_error

   .. automethod:: _read_dns_name
   .. automethod:: _read_rdata_name
   .. automethod:: _make_dns_name
   .. automethod:: _read_dns_opt
   .. automethod:: _make_dns_opt
   .. automethod:: _read_dns_options
   .. automethod:: _make_dns_options
   .. automethod:: _import_next_layer
   .. automethod:: _import_next_message

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.application.dns.protocol._opens_whole_message
.. autofunction:: pcapkit.protocols.application.dns.protocol._sections_end
.. autofunction:: pcapkit.protocols.application.dns.protocol._frames_message

Header Schemas
--------------

.. module:: pcapkit.protocols.application.dns.schema

.. autoclass:: pcapkit.protocols.application.dns.schema.DNS
   :members:
   :show-inheritance:

Domain Name Codec
~~~~~~~~~~~~~~~~~

The codec works on octets and labels, with no protocol state, so another
protocol carrying domain names can call it.

.. autofunction:: pcapkit.protocols.application.dns.schema.read_name
.. autofunction:: pcapkit.protocols.application.dns.schema.make_name
.. autofunction:: pcapkit.protocols.application.dns.schema.compress_name
.. autofunction:: pcapkit.protocols.application.dns.schema.record_name
.. autofunction:: pcapkit.protocols.application.dns.schema.name_to_text
.. autofunction:: pcapkit.protocols.application.dns.schema.text_to_labels
.. autofunction:: pcapkit.protocols.application.dns.schema.dns_body_length

.. data:: HEADER_LENGTH
   :value: 12

   Length of the fixed header, before the sections.

.. data:: POINTER_LIMIT
   :value: 16383

   Largest offset a compression pointer can carry, in its 14 bits.

Data Models
-----------

.. module:: pcapkit.protocols.application.dns.data

.. autoclass:: pcapkit.protocols.application.dns.data.DNS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.Flags
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.Name
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.Question
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.ResourceRecord
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.OPT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.Option
   :members:
   :show-inheritance:

RDATA
~~~~~

.. autoclass:: pcapkit.protocols.application.dns.data.RData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.A
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.NS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.CNAME
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.SOA
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.PTR
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.MX
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.TXT
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.AAAA
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.SRV
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.CAA
   :members:
   :show-inheritance:

EDNS(0) Options
~~~~~~~~~~~~~~~

.. autoclass:: pcapkit.protocols.application.dns.data.OptionData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.ClientSubnet
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.Cookie
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.TCPKeepalive
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.application.dns.data.ExtendedError
   :members:
   :show-inheritance:
