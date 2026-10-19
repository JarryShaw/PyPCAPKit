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

   :param dict\_: Source data, read as by :meth:`~pcapkit.corekit.infoclass.Info.from_dict`,
      except that no value is rebuilt into the :class:`~pcapkit.corekit.infoclass.Info`
      subclass its key's annotation names.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: __additional__
      :no-value:
   .. autoattribute:: __excluded__
      :no-value:

   .. autoattribute:: __map__
   .. autoattribute:: __map_reverse__

.. autodecorator:: pcapkit.corekit.infoclass.info_final

.. autoclass:: pcapkit.corekit.infoclass.MultiInfo
   :no-members:
   :show-inheritance:

   .. automethod:: to_dict

.. autoclass:: pcapkit.corekit.infoclass.OrderedMultiInfo
   :no-members:
   :show-inheritance:

   .. automethod:: to_dict

Internal Definitions
--------------------

.. autoclass:: pcapkit.corekit.infoclass.InfoMeta
   :no-members:
   :show-inheritance:

   .. automethod:: __new__

.. autoclass:: pcapkit.corekit.infoclass.FinalisedState
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.corekit.infoclass._MultiInfo
   :no-members:
   :show-inheritance:

   .. automethod:: __new__
   .. automethod:: __update__
   .. automethod:: __setattr__

.. autoclass:: pcapkit.corekit.infoclass._OrderedMultiDict
   :no-members:
   :show-inheritance:

   .. automethod:: __ne__
   .. automethod:: __repr__

.. autofunction:: pcapkit.corekit.infoclass._ne

Type Variables
--------------

.. data:: KT
   :type: typing.Any

.. data:: VT
   :type: typing.Any

.. data:: ST
   :type: typing.Type[pcapkit.corekit.infoclass.Info]
