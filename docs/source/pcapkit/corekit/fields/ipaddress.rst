IP Address Fields
-----------------

.. module:: pcapkit.corekit.fields.ipaddress

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

Type Variables
~~~~~~~~~~~~~~

.. data:: pcapkit.corekit.fields.ipaddress._T
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Interface | ipaddress.IPv6Interface

.. data:: pcapkit.corekit.fields.ipaddress._AT
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

.. data:: pcapkit.corekit.fields.ipaddress._IT
   :type: ipaddress.IPv4Interface | ipaddress.IPv6Interface
