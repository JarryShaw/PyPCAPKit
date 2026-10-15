Base Fields
===========

.. module:: pcapkit.corekit.fields.field

.. versionremoved:: 1.5.0

   ``pcapkit.corekit.fields.field.NoValueType``, now
   :class:`pcapkit.corekit.sentinels.NoValueType` (:issue:`911`,
   :issue:`1744`), and ``pcapkit.corekit.fields.field.NoValue``, now
   :data:`pcapkit.corekit.sentinels.NO_VALUE` (:issue:`937`).

.. autoclass:: pcapkit.corekit.fields.field.Field
   :members:
   :show-inheritance:

   .. autoattribute:: _length
   .. autoattribute:: _length_callback

.. autoclass:: pcapkit.corekit.fields.field.FieldBase
   :members:
   :show-inheritance:

   .. autoattribute:: _name
   .. autoattribute:: _template
   .. autoattribute:: _default
   .. autoattribute:: _callback

Internal Definitions
--------------------

.. autoclass:: pcapkit.corekit.fields.field.FieldMeta
   :members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.corekit.fields.field._T
   :type: typing.Any
