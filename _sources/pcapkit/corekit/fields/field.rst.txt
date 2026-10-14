Base Fields
===========

.. module:: pcapkit.corekit.fields.field

.. versionremoved:: 1.5.0

   Moved to :mod:`pcapkit.utilities.config` (:issue:`1726`):

   * ``pcapkit.corekit.fields.field._MAX_ZERO_PAD_LENGTH``, now
     :data:`pcapkit.utilities.config.MAX_ZERO_PAD_LENGTH`, set with
     :envvar:`PCAPKIT_MAX_ZERO_PAD_LENGTH`;
   * ``pcapkit.corekit.fields.field._MAX_ZERO_PAD_SHORTFALL``, now
     :data:`pcapkit.utilities.config.MAX_ZERO_PAD_SHORTFALL`, set with
     :envvar:`PCAPKIT_MAX_ZERO_PAD_SHORTFALL`;
   * ``pcapkit.corekit.fields.field._ZERO_PAD_BUDGET_RATIO``, now
     :data:`pcapkit.utilities.config.ZERO_PAD_BUDGET_RATIO`, set with
     :envvar:`PCAPKIT_ZERO_PAD_BUDGET_RATIO`.

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

Auxiliaries
-----------

.. autoclass:: pcapkit.corekit.fields.field.NoValueType
.. autodata:: pcapkit.corekit.fields.field.NO_VALUE
   :no-value:

Internal Definitions
--------------------

.. autoclass:: pcapkit.corekit.fields.field.FieldMeta
   :members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.corekit.fields.field._T
   :type: typing.Any
