IP Address Fields
-----------------

.. module:: pcapkit.corekit.fields.ipaddress

.. versionchanged:: 1.5.0

   Every field here rejects a :obj:`bool` with
   :exc:`~pcapkit.utilities.exceptions.FieldValueError`, where an IPv4 field
   packed :obj:`True` and :obj:`False` as ``0.0.0.1`` and ``0.0.0.0``
   (:issue:`491`).

IP Addresses
~~~~~~~~~~~~

.. autoclass:: pcapkit.corekit.fields.ipaddress.IPv4AddressField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress.IPv6AddressField
   :members:
   :show-inheritance:

IP Interface
~~~~~~~~~~~~

.. autoclass:: pcapkit.corekit.fields.ipaddress.IPv4InterfaceField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress.IPv6InterfaceField
   :members:
   :show-inheritance:

Construction Helpers
~~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.corekit.fields.ipaddress.parse_ip_address

Internal Definitions
~~~~~~~~~~~~~~~~~~~~

.. autoclass:: pcapkit.corekit.fields.ipaddress._IPField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress._IPAddressField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress._IPInterfaceField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress._RawMaskIPv4Interface
   :members:
   :show-inheritance:

.. autofunction:: pcapkit.corekit.fields.ipaddress._reject_bool

Type Variables
~~~~~~~~~~~~~~

.. data:: _T
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Interface | ipaddress.IPv6Interface

.. data:: _AT
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

.. data:: _IT
   :type: ipaddress.IPv4Interface | ipaddress.IPv6Interface
