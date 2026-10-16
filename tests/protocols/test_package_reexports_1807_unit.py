# -*- coding: utf-8 -*-
"""Every data and schema package re-exports what its submodules export (#1807).

#1797 found :mod:`pcapkit.protocols.data.link` without the L2TP data model, and
the test #1806 added checks that one package. The same gap was open in others:
the Mobility Header messages, options, suboptions and attributes on both sides,
the HOPOPT and IPv6-Opts ``SMFDPDOption`` and ``QuickStartOption`` bases, the
PCAP-NG ``PacketBlock`` and its ``PACK_*`` options, the HTTP/2 ``Settings`` data
model, and the schemas ``ipv4.Option`` and ``ipv6_route.RoutingType``.

:mod:`tests.project.test_public_api` cannot see such a gap: its converse reads
the attributes a package *holds*, and a name the package never imported is not
one of them. So this module walks every package under
:mod:`pcapkit.protocols.data` and :mod:`pcapkit.protocols.schema` and checks it
against the :attr:`__all__` of each of its children. The check is by identity,
because a package re-exports a nested name under its protocol's prefix
(``MH_Option``, ``PCAPNG_EPB_FlagsOption``), so the child's name need not be the
package's.

It also checks that a star-import inside a package is never shadowed, which is
what keeps ``from pcapkit.protocols.data import *`` (and ``schema``) from binding
one name to two objects.

Nothing here reads a capture, so this belongs to the unit tier.

"""
from __future__ import annotations

import ast
import importlib
import pkgutil
import types
import unittest

#: The two trees this module covers; each root is itself a package.
ROOTS = ('pcapkit.protocols.data', 'pcapkit.protocols.schema')

#: Names a submodule lists in :attr:`__all__` that its package deliberately does
#: not re-export, keyed by the submodule. An entry is an API decision to be argued
#: for in review, not the way to quiet a failure.
#:
#: :mod:`pcapkit.protocols.schema.internet.ipv6_option` holds field callbacks
#: shared by the HOPOPT and IPv6-Opts option schemas, and its own documentation
#: page is where they are published. No schema package re-exports a field
#: callback: the sibling modules (``hopopt``, ``mh``, ``hip``, ``ipv4``) keep
#: theirs out of :attr:`__all__` altogether. A bare package-level name would
#: also be ambiguous, since ``hopopt`` and ``ipv6_opts`` each define wrappers of
#: the same names bound to their own header, and ``mh`` and ``ipv4`` define
#: unrelated ``pad_opt_data_len`` and ``quick_start_data_selector`` callbacks.
MODULE_ONLY = {
    'pcapkit.protocols.schema.internet.ipv6_option': (
        'rpl_opt_sub_tlv_len', 'mpl_opt_seed_id_len', 'smf_i_dpd_id_len',
        'smf_dpd_data_selector', 'smf_i_dpd_tid_selector', 'quick_start_data_selector',
        'pad_opt_data_len', 'calipso_pad_len', 'mpl_opt_pad_len',
    ),
}  # type: dict[str, tuple[str, ...]]


def _is_public(name: 'str') -> 'bool':
    return not name.rsplit('.', 1)[-1].startswith('_')


def packages() -> 'list[str]':
    """Every public package under :data:`ROOTS`, the roots included."""
    found = []  # type: list[str]

    def walk(name: 'str') -> None:
        found.append(name)
        package = importlib.import_module(name)
        for info in pkgutil.iter_modules(package.__path__, name + '.'):
            if info.ispkg and _is_public(info.name):
                walk(info.name)

    for root in ROOTS:
        walk(root)
    return found


def children(package: 'types.ModuleType') -> 'list[types.ModuleType]':
    """The public modules and packages directly below ``package``."""
    return [importlib.import_module(info.name)
            for info in pkgutil.iter_modules(package.__path__, package.__name__ + '.')
            if _is_public(info.name)]


def exported_objects(package: 'types.ModuleType') -> 'set[int]':
    """Identities of the objects ``from package import *`` binds."""
    return {id(getattr(package, name)) for name in package.__all__}


def star_imported(package: 'types.ModuleType') -> 'list[str]':
    """The modules ``package``'s :file:`__init__.py` imports with ``import *``."""
    with open(package.__file__, encoding='utf-8') as file:
        tree = ast.parse(file.read())
    return [node.module for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module is not None
            and any(alias.name == '*' for alias in node.names)]


class PackageReexportTests(unittest.TestCase):
    def test_the_walk_finds_the_layer_packages(self) -> None:
        # A broken walk would make every check below pass over nothing.
        found = packages()
        for root in ROOTS:
            for layer in ('link', 'internet', 'transport', 'application', 'misc', 'misc.pcap'):
                self.assertIn(f'{root}.{layer}', found)

    def test_every_child_declares_all(self) -> None:
        # The rule below reads each child's __all__; a child without one would
        # pass it vacuously.
        undeclared = [child.__name__ for name in packages()
                      for child in children(importlib.import_module(name))
                      if not hasattr(child, '__all__')]
        self.assertEqual(undeclared, [])

    def test_every_package_reexports_every_child_export(self) -> None:
        missing = {}  # type: dict[str, list[str]]
        for name in packages():
            package = importlib.import_module(name)
            exported = exported_objects(package)
            for child in children(package):
                allowed = MODULE_ONLY.get(child.__name__, ())
                unexported = [symbol for symbol in getattr(child, '__all__', ())
                              if symbol not in allowed
                              and id(getattr(child, symbol)) not in exported]
                if unexported:
                    missing[f'{name} <- {child.__name__}'] = unexported

        self.assertEqual(missing, {},
                         'these packages do not re-export names their submodules list in '
                         '__all__; re-export each under the <protocol>_<name> alias its '
                         'siblings use, or record it in MODULE_ONLY with the reason')

    def test_the_module_only_allowlist_is_tight(self) -> None:
        # An entry that no longer names a real, still-unexported child name would
        # silently excuse the next omission of that name.
        walked = {child.__name__: (name, child) for name in packages()
                  for child in children(importlib.import_module(name))}
        self.assertEqual(sorted(set(MODULE_ONLY) - set(walked)), [],
                         'MODULE_ONLY names modules outside the walk')

        stale = {}  # type: dict[str, list[str]]
        for module, allowed in MODULE_ONLY.items():
            if module not in walked:
                continue
            name, child = walked[module]
            exported = exported_objects(importlib.import_module(name))
            dead = [symbol for symbol in allowed
                    if symbol not in getattr(child, '__all__', ())
                    or id(getattr(child, symbol)) in exported]
            if dead:
                stale[module] = dead
        self.assertEqual(stale, {},
                         'MODULE_ONLY entries the module no longer lists in __all__, or '
                         'that its package now exports anyway')

    def test_star_imports_are_never_shadowed(self) -> None:
        # A package that star-imports its children ends up with one object per
        # name. If two children export the same name, or a later import rebinds
        # it, one of them is silently lost -- so every name a star-imported child
        # exports has to reach the package as that same object.
        shadowed = {}  # type: dict[str, list[str]]
        for name in packages():
            package = importlib.import_module(name)
            for source in star_imported(package):
                child = importlib.import_module(source)
                lost = [symbol for symbol in child.__all__
                        if getattr(package, symbol, None) is not getattr(child, symbol)]
                if lost:
                    shadowed[f'{name} <- {source}'] = lost

        self.assertEqual(shadowed, {},
                         'these names are bound to a different object in the package than '
                         'in the child that star-exports them')

    def test_aggregator_star_imports_bind_the_reported_names(self) -> None:
        # The statement from the issue, on one name from each gap it reported.
        from pcapkit.protocols.data.application import httpv2 as data_httpv2
        from pcapkit.protocols.data.internet import hopopt as data_hopopt
        from pcapkit.protocols.data.internet import ipv6_opts as data_ipv6_opts
        from pcapkit.protocols.data.internet import mh as data_mh
        from pcapkit.protocols.data.misc import pcapng as data_pcapng
        from pcapkit.protocols.schema.internet import ipv4 as schema_ipv4
        from pcapkit.protocols.schema.internet import ipv6_route as schema_ipv6_route
        from pcapkit.protocols.schema.internet import mh as schema_mh
        from pcapkit.protocols.schema.misc import pcapng as schema_pcapng

        expected = {
            'pcapkit.protocols.data': {
                'HTTPv2_Settings': data_httpv2.Settings,
                'HOPOPT_QuickStartOption': data_hopopt.QuickStartOption,
                'IPv6_Opts_SMFDPDOption': data_ipv6_opts.SMFDPDOption,
                'MH_FastBindingUpdateMessage': data_mh.FastBindingUpdateMessage,
                'MH_QoSAttribute': data_mh.QoSAttribute,
                'PCAPNG_PacketBlock': data_pcapng.PacketBlock,
                'PCAPNG_PACK_FlagsOption': data_pcapng.PACK_FlagsOption,
            },
            'pcapkit.protocols.schema': {
                'IPv4_Option': schema_ipv4.Option,
                'IPv6_Route_RoutingType': schema_ipv6_route.RoutingType,
                'MH_ExperimentalExtension': schema_mh.ExperimentalExtension,
                'PCAPNG_PACK_HashOption': schema_pcapng.PACK_HashOption,
            },
        }  # type: dict[str, dict[str, object]]
        for module, names in expected.items():
            namespace = {}  # type: dict[str, object]
            exec(f'from {module} import *', namespace)  # pylint: disable=exec-used
            with self.subTest(module=module):
                self.assertEqual({name: namespace.get(name) for name in names}, names)


if __name__ == '__main__':
    unittest.main()
