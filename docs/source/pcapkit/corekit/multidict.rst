Multi-Mapping Dictionary
========================

.. module:: pcapkit.corekit.multidict

:mod:`pcapkit.corekit.multidict` contains dictionaries that store multiple
values per key, based on the `Werkzeug`_ project.

.. autoclass:: pcapkit.corekit.multidict.MultiDict
   :no-members:
   :no-special-members: __init__
   :show-inheritance:

   .. automethod:: add
   .. automethod:: get
   .. automethod:: getlist
   .. automethod:: setlist
   .. automethod:: setdefault
   .. automethod:: setlistdefault
   .. automethod:: items
   .. automethod:: lists
   .. automethod:: values
   .. automethod:: listvalues
   .. automethod:: to_dict
   .. automethod:: update
   .. automethod:: pop
   .. automethod:: popitem
   .. automethod:: poplist
   .. automethod:: popitemlist

.. autoclass:: pcapkit.corekit.multidict.OrderedMultiDict
   :no-members:
   :no-special-members: __init__
   :show-inheritance:

   .. automethod:: deepcopy

Type Variables
--------------

.. data:: _T
   :type: typing.Any

.. data:: _KT
   :type: typing.Any

.. data:: _VT
   :type: typing.Any
