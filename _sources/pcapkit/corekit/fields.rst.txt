Protocol Fields
===============

.. module:: pcapkit.corekit.fields

:mod:`pcapkit.corekit.fields` is collection of protocol fields,
descriptive of the structure of protocol headers.

Base Field
----------

.. module:: pcapkit.corekit.fields.field

.. autoclass:: pcapkit.corekit.fields.field._Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.field.Field
   :members:
   :show-inheritance:

Auxiliary
~~~~~~~~~

.. autoclass:: pcapkit.corekit.fields.field.NoValueType
.. autodata:: pcapkit.corekit.fields.field.NoValue
   :no-value:

Numerical Fields
----------------

.. module:: pcapkit.corekit.fields.numbers

.. autoclass:: pcapkit.corekit.fields.numbers.NumberField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.Int32Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.UInt32Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.Int16Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.UInt16Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.Int64Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.UInt64Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.Int8Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.UInt8Field
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.numbers.EnumField
   :members:
   :show-inheritance:

Text Fields
-----------

.. module:: pcapkit.corekit.fields.strings

.. autoclass:: pcapkit.corekit.fields.strings._TextField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.strings.BytesField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.strings.StringField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.strings.BitField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.strings.PaddingField
   :members:
   :show-inheritance:

IP Address Fields
-----------------

.. module:: pcapkit.corekit.fields.ipaddress

.. autoclass:: pcapkit.corekit.fields.ipaddress._IPField
   :members:
   :show-inheritance:

IP Addresses
~~~~~~~~~~~~

.. autoclass:: pcapkit.corekit.fields.ipaddress._IPAddressField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress.IPv4AddressField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress.IPv6AddressField
   :members:
   :show-inheritance:

IP Interface
~~~~~~~~~~~~

.. autoclass:: pcapkit.corekit.fields.ipaddress._IPInterfaceField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress.IPv4InterfaceField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.ipaddress.IPv6InterfaceField
   :members:
   :show-inheritance:

Container Fields
----------------

.. module:: pcapkit.corekit.fields.collections

.. autoclass:: pcapkit.corekit.fields.collections.ListField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.collections.OptionField
   :members:
   :show-inheritance:

Miscellaneous Fields
--------------------

.. module:: pcapkit.corekit.fields.misc

.. autoclass:: pcapkit.corekit.fields.misc.ConditionalField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.misc.PayloadField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.misc.SwitchField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.misc.ForwardMatchField
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.fields.misc.NoValueField
   :members:
   :show-inheritance:
