Info Class
==========

.. module:: pcapkit.corekit.infoclass

:mod:`pcapkit.corekit.infoclass` contains the :obj:`dict`-like class
:class:`~pcapkit.corekit.infoclass.Info`, modelled on
:func:`dataclasses.dataclass` (:pep:`557`), and the immutable multi-mapping
classes :class:`~pcapkit.corekit.infoclass.MultiInfo` and
:class:`~pcapkit.corekit.infoclass.OrderedMultiInfo` that a finalised
:class:`~pcapkit.corekit.infoclass.Info` holds its option lists in.

.. autoclass:: pcapkit.corekit.infoclass.Info
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __init_subclass__
   .. automethod:: __post_init__

   .. autoattribute:: __additional__
      :no-value:
   .. autoattribute:: __excluded__
      :no-value:

.. autodecorator:: pcapkit.corekit.infoclass.info_final

.. autoclass:: pcapkit.corekit.infoclass.MultiInfo
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.infoclass.OrderedMultiInfo
   :no-members:
   :show-inheritance:

Internal Definitions
--------------------

.. autoclass:: pcapkit.corekit.infoclass.InfoMeta
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.infoclass._MultiInfo
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.infoclass._OrderedMultiDict
   :no-members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.corekit.infoclass.KT
   :type: typing.Any

.. data:: pcapkit.corekit.infoclass.VT
   :type: typing.Any

.. data:: pcapkit.corekit.infoclass.ST
   :type: typing.Type[pcapkit.corekit.infoclass.Info]
