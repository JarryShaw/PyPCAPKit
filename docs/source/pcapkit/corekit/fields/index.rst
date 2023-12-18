Protocol Fields
===============

.. module:: pcapkit.corekit.fields

:mod:`pcapkit.corekit.fields` is collection of protocol fields,
descriptive of the structure of protocol headers.

.. toctree::
   :maxdepth: 2

   field
   numbers
   strings
   ipaddress
   collections
   misc

All field classes are implemented as :class:`~pcapkit.corekit.fields.field.FieldBase`
subclasses, which are responsible for parsing and/or formatting the field value
following the pre-defined mechanisms. Below is a brief diagram of the class
hierarchy of :mod:`pcapkit.corekit.fields`:

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

       click A "/pcapkit/corekit/fields/field.html#pcapkit.corekit.fields.field.FieldMeta"
       click B "/pcapkit/corekit/fields/field.html#pcapkit.corekit.fields.field.FieldBase"
       click C "/pcapkit/corekit/fields/field.html#pcapkit.corekit.fields.field.Field"

       click NumberField "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.NumberField"
       click Int64Field "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.Int64Field"
       click UInt64Field "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.UInt64Field"
       click Int32Field "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.Int32Field"
       click UInt32Field "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.UInt32Field"
       click Int16Field "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.Int16Field"
       click UInt16Field "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.UInt16Field"
       click Int8Field "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.Int8Field"
       click UInt8Field "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.UInt8Field"
       click EnumField "/pcapkit/corekit/fields/numbers.html#pcapkit.corekit.fields.numbers.EnumField"

       click _TextField "/pcapkit/corekit/fields/strings.html#pcapkit.corekit.fields.strings._TextField"
       click BytesField "/pcapkit/corekit/fields/strings.html#pcapkit.corekit.fields.strings.BytesField"
       click StringField "/pcapkit/corekit/fields/strings.html#pcapkit.corekit.fields.strings.StringField"
       click BitField "/pcapkit/corekit/fields/strings.html#pcapkit.corekit.fields.strings.BitField"
       click PaddingField "/pcapkit/corekit/fields/strings.html#pcapkit.corekit.fields.strings.PaddingField"

       click _IPField "/pcapkit/corekit/fields/ipaddress.html#pcapkit.corekit.fields.ipaddress._IPField"
       click _IPAddressField "/pcapkit/corekit/fields/ipaddress.html#pcapkit.corekit.fields.ipaddress._IPAddressField"
       click _IPInterfaceField "/pcapkit/corekit/fields/ipaddress.html#pcapkit.corekit.fields.ipaddress._IPInterfaceField"
       click IPv4AddressField "/pcapkit/corekit/fields/ipaddress.html#pcapkit.corekit.fields.ipaddress.IPv4AddressField"
       click IPv6AddressField "/pcapkit/corekit/fields/ipaddress.html#pcapkit.corekit.fields.ipaddress.IPv6AddressField"
       click IPv4InterfaceField "/pcapkit/corekit/fields/ipaddress.html#pcapkit.corekit.fields.ipaddress.IPv4InterfaceField"
       click IPv6InterfaceField "/pcapkit/corekit/fields/ipaddress.html#pcapkit.corekit.fields.ipaddress.IPv6InterfaceField"

       click ListField "/pcapkit/corekit/fields/collections.html#pcapkit.corekit.fields.collections.ListField"
       click OptionField "/pcapkit/corekit/fields/collections.html#pcapkit.corekit.fields.collections.OptionField"

       click NoValueField "/pcapkit/corekit/fields/misc.html#pcapkit.corekit.fields.misc.NoValueField"
       click ConditionalField "/pcapkit/corekit/fields/misc.html#pcapkit.corekit.fields.misc.ConditionalField"
       click PayloadField "/pcapkit/corekit/fields/misc.html#pcapkit.corekit.fields.misc.PayloadField"
       click SwitchField "/pcapkit/corekit/fields/misc.html#pcapkit.corekit.fields.misc.SwitchField"
       click SchemaField "/pcapkit/corekit/fields/misc.html#pcapkit.corekit.fields.misc.SchemaField"
       click ForwardMatchField "/pcapkit/corekit/fields/misc.html#pcapkit.corekit.fields.misc.ForwardMatchField"
