Protocol Fields
===============

.. module:: pcapkit.corekit.fields

:mod:`pcapkit.corekit.fields` is the collection of protocol fields that
describe the structure of protocol headers.

.. toctree::
   :maxdepth: 2

   field
   numbers
   strings
   ipaddress
   collections
   misc
   byteorder

Every field class is a :class:`~pcapkit.corekit.fields.field.FieldBase`
subclass, responsible for parsing and/or formatting the field value. The class
hierarchy:

.. mermaid::

   flowchart LR
       A{{FieldMeta}} -.->|metaclass| B(FieldBase)
       B --> C(Field)

       subgraph numbers [Numerical Fields]
           %% direction TD

           NumberField --> Int64Field & UInt64Field
           NumberField --> Int32Field & UInt32Field
           NumberField --> Int16Field & UInt16Field
           NumberField --> Int8Field & UInt8Field
           NumberField --> EnumField
           EnumField --> PortEnumField
       end
       C --> NumberField

       subgraph strings [Text Fields]
           %% direction TD

           _TextField --> BytesField & StringField
           _TextField --> BitField
           BytesField --> PaddingField
       end
       C --> _TextField

       subgraph ipaddress [IP Address Fields]
           %% direction TD

           _IPField --> _IPAddressField & _IPInterfaceField
           _IPAddressField --> IPv4AddressField & IPv6AddressField
           _IPInterfaceField --> IPv4InterfaceField & IPv6InterfaceField
       end
       C --> _IPField

       subgraph collections [Container Fields]
           %% direction TD

           ListField --> OptionField
       end
       B --> ListField

       subgraph misc [Miscellaneous Fields]
           %% direction TD

           NoValueField & ConditionalField & PayloadField
           SwitchField & SchemaField & ForwardMatchField
       end
       B --> NoValueField & ConditionalField & PayloadField
       B --> SwitchField & SchemaField & ForwardMatchField

       C --> D([user customisation ...])

       click A "field.html#pcapkit.corekit.fields.field.FieldMeta"
       click B "field.html#pcapkit.corekit.fields.field.FieldBase"
       click C "field.html#pcapkit.corekit.fields.field.Field"

       click NumberField "numbers.html#pcapkit.corekit.fields.numbers.NumberField"
       click Int64Field "numbers.html#pcapkit.corekit.fields.numbers.Int64Field"
       click UInt64Field "numbers.html#pcapkit.corekit.fields.numbers.UInt64Field"
       click Int32Field "numbers.html#pcapkit.corekit.fields.numbers.Int32Field"
       click UInt32Field "numbers.html#pcapkit.corekit.fields.numbers.UInt32Field"
       click Int16Field "numbers.html#pcapkit.corekit.fields.numbers.Int16Field"
       click UInt16Field "numbers.html#pcapkit.corekit.fields.numbers.UInt16Field"
       click Int8Field "numbers.html#pcapkit.corekit.fields.numbers.Int8Field"
       click UInt8Field "numbers.html#pcapkit.corekit.fields.numbers.UInt8Field"
       click EnumField "numbers.html#pcapkit.corekit.fields.numbers.EnumField"
       click PortEnumField "numbers.html#pcapkit.corekit.fields.numbers.PortEnumField"

       click _TextField "strings.html#pcapkit.corekit.fields.strings._TextField"
       click BytesField "strings.html#pcapkit.corekit.fields.strings.BytesField"
       click StringField "strings.html#pcapkit.corekit.fields.strings.StringField"
       click BitField "strings.html#pcapkit.corekit.fields.strings.BitField"
       click PaddingField "strings.html#pcapkit.corekit.fields.strings.PaddingField"

       click _IPField "ipaddress.html#pcapkit.corekit.fields.ipaddress._IPField"
       click _IPAddressField "ipaddress.html#pcapkit.corekit.fields.ipaddress._IPAddressField"
       click _IPInterfaceField "ipaddress.html#pcapkit.corekit.fields.ipaddress._IPInterfaceField"
       click IPv4AddressField "ipaddress.html#pcapkit.corekit.fields.ipaddress.IPv4AddressField"
       click IPv6AddressField "ipaddress.html#pcapkit.corekit.fields.ipaddress.IPv6AddressField"
       click IPv4InterfaceField "ipaddress.html#pcapkit.corekit.fields.ipaddress.IPv4InterfaceField"
       click IPv6InterfaceField "ipaddress.html#pcapkit.corekit.fields.ipaddress.IPv6InterfaceField"

       click ListField "collections.html#pcapkit.corekit.fields.collections.ListField"
       click OptionField "collections.html#pcapkit.corekit.fields.collections.OptionField"

       click NoValueField "misc.html#pcapkit.corekit.fields.misc.NoValueField"
       click ConditionalField "misc.html#pcapkit.corekit.fields.misc.ConditionalField"
       click PayloadField "misc.html#pcapkit.corekit.fields.misc.PayloadField"
       click SwitchField "misc.html#pcapkit.corekit.fields.misc.SwitchField"
       click SchemaField "misc.html#pcapkit.corekit.fields.misc.SchemaField"
       click ForwardMatchField "misc.html#pcapkit.corekit.fields.misc.ForwardMatchField"
