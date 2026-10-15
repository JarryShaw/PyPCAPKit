# -*- coding: utf-8 -*-
"""The L2TP data model is exported with its link-layer siblings (#1797).

:mod:`pcapkit.protocols.data.link` re-exported the data models of ARP, Ethernet,
Loopback and VLAN but not :mod:`pcapkit.protocols.data.link.l2tp`, although
:mod:`pcapkit.protocols.schema.link` exports the schema of the same name. The
omission was not a decision: the data model arrived in ``cdb5fef3f`` without
touching the package, and no commit has ever named ``L2TP`` in it.

:mod:`tests.project.test_public_api` could not see the gap. Its converse
assertion reads the attributes a package *holds*, and a name the package never
imported is not one of them -- so these cases check the package against the
``__all__`` of each of its children instead.

Nothing here reads a capture, so this belongs to the unit tier.

"""
from __future__ import annotations

import importlib
import pkgutil
import unittest


class L2TPDataExportTests(unittest.TestCase):
    def test_link_package_reexports_every_child_export(self) -> None:
        # Identity rather than name: siblings re-export nested models under a
        # protocol prefix (``ARP_Address``, ``VLAN_TCI``), so the child's name
        # need not be the package's.
        package = importlib.import_module('pcapkit.protocols.data.link')
        exported = {id(getattr(package, name)) for name in package.__all__}

        children = [info.name for info in pkgutil.iter_modules(package.__path__, package.__name__ + '.')]
        self.assertIn('pcapkit.protocols.data.link.l2tp', children)

        missing = {}  # type: dict[str, list[str]]
        for child_name in children:
            child = importlib.import_module(child_name)
            unexported = [name for name in getattr(child, '__all__', ())
                          if id(getattr(child, name)) not in exported]
            if unexported:
                missing[child_name] = unexported

        self.assertEqual(missing, {},
                         'pcapkit.protocols.data.link does not re-export these names '
                         'its submodules list in __all__')

    def test_star_imports_bind_the_l2tp_models(self) -> None:
        # ``Flags`` takes the ``<protocol>_<name>`` alias its siblings use
        # (``IPv4_Flags``, ``TCP_Flags``) once it leaves its own module.
        from pcapkit.protocols.data.link import l2tp

        for module, flags in (('pcapkit.protocols.data.link.l2tp', 'Flags'),
                              ('pcapkit.protocols.data.link', 'L2TP_Flags'),
                              ('pcapkit.protocols.data', 'L2TP_Flags')):
            namespace = {}  # type: dict[str, object]
            exec(f'from {module} import *', namespace)  # pylint: disable=exec-used
            with self.subTest(module=module):
                self.assertIs(namespace.get('L2TP'), l2tp.L2TP)
                self.assertIs(namespace.get(flags), l2tp.Flags)


if __name__ == '__main__':
    unittest.main()
