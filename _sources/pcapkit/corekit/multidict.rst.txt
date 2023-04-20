Multi-Mapping Dictionary
========================

.. module:: pcapkit.corekit.multidict

:mod:`pcapkit.corekit.multidict` contains multi-mapping dictionary classes,
which are used to store multiple mappings of the same key. The implementation
is inspired and based on the `Werkzeug`_ project.

.. _Werkzeug: https://werkzeug.palletsprojects.com/

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
