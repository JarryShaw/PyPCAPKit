# -*- coding: utf-8 -*-
"""Every class-level registry map has its registration wrapper. C.f. #2511.

The owner ruled that each dispatch map a protocol class keeps -- ``__proto__``,
``__option__``, ``__chunk__`` and the rest -- is written through a public
``register_*`` wrapper in :mod:`pcapkit.foundation.registry.protocols`, which
validates the code and the target before calling the owning class's
``register`` classmethod. Each wrapper names the map it writes in a
``# NOTE: <map path>`` line directly above its ``def``, and that tag is what this
module reads.

The maps are found by walking every :class:`~pcapkit.protocols.protocol.ProtocolBase`
descendant for a dunder :class:`dict` in its own :func:`vars`, so a map added
tomorrow fails here until it has a wrapper or an entry in ``EXCUSED``. The
table is checked in both directions: an excused map that gains a wrapper, or
stops existing, fails too.

The classmethod is the owning class's own -- ``register`` for ``__proto__``,
``register_<kind>`` for ``__<kind>__`` -- unless ``INHERITED`` names the one it
inherits and why that one is typed for exactly the map's keys, the owner's
option 2 on #2511. That table is checked in both directions as well.

The behaviour of the wrappers and classmethods #2511 added is pinned at the end:
each writes the owning class's map and warns in its own key's terms, and
``register_ipx`` and ``register_loopback`` dispatch a parse to what they
registered.

"""

import importlib
import inspect
import io
import pkgutil
import re
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): a structural sweep over every protocol class.
__tier__ = 'LATEST'

#: ``map path -> why it has no wrapper``. Each reason names where the gap is
#: owned, so that closing it deletes the entry here.
EXCUSED = {
    'pcapkit.protocols.protocol.ProtocolBase.__proto__':
        'the empty default a class without a map of its own inherits; nothing dispatches by it',
}

#: ``map path -> (the classmethod its owner inherits, why it fits the map's keys)``.
INHERITED = {
    'pcapkit.protocols.transport.tcp.TCP.__proto__':
        ('pcapkit.protocols.transport.transport.Transport.register', 'typed for the port the map is keyed by'),
    'pcapkit.protocols.transport.udp.UDP.__proto__':
        ('pcapkit.protocols.transport.transport.Transport.register', 'typed for the port the map is keyed by'),
}

#: A wrapper's tag: one or more map paths on the comment line above its ``def``.
TAG = re.compile(r'^# NOTE: (?P<paths>\S.*)\ndef (?P<name>register_\w+)\(', re.MULTILINE)


def _import_protocols() -> None:
    """Import every shipped protocol module, so every class is a subclass by now."""
    import pcapkit.protocols as package

    for info in pkgutil.walk_packages(package.__path__, 'pcapkit.protocols.'):
        if 'NotImplemented' not in info.name:
            importlib.import_module(info.name)


def _maps() -> 'dict[str, type]':
    """The class holding each dunder :class:`dict` in its own :func:`vars`, by path."""
    from pcapkit.protocols.protocol import ProtocolBase

    _import_protocols()
    found = {}  # type: dict[str, type]
    seen = set()  # type: set[type]
    pending = [ProtocolBase]  # type: list[type]
    while pending:
        klass = pending.pop()
        if klass in seen:
            continue
        seen.add(klass)
        pending.extend(klass.__subclasses__())
        for name, value in vars(klass).items():
            if (name.startswith('__') and name.endswith('__') and name != '__annotations__'
                    and isinstance(value, dict)):
                found[f'{klass.__module__}.{klass.__qualname__}.{name}'] = klass
    return found


def _classmethod_name(path: 'str') -> 'str':
    """The ``register*`` classmethod writing the map at ``path``."""
    kind = path.rpartition('.')[2][2:-2]
    return 'register' if kind == 'proto' else f'register_{kind}'


def _resolve(path: 'str') -> 'object':
    """The object a dotted ``module.Class.attr`` path names."""
    parts = path.split('.')
    for cut in range(len(parts) - 1, 0, -1):
        try:
            target = importlib.import_module('.'.join(parts[:cut]))
        except ImportError:
            continue
        for attr in parts[cut:]:
            target = vars(target)[attr] if isinstance(target, type) else getattr(target, attr)
        return target
    raise AssertionError(path)


def _tags() -> 'dict[str, list[str]]':
    """``wrapper name -> the map paths its tag names``."""
    from pcapkit.foundation.registry import protocols

    source = inspect.getsource(protocols)
    return {match['name']: [path.strip() for path in match['paths'].split(',')]
            for match in TAG.finditer(source)}


class RegistryWrapperCoverageTests(unittest.TestCase):
    """Each map is tagged by a public wrapper, or excused with a reason."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_tag_names_a_real_map_of_a_public_wrapper(self) -> None:
        from pcapkit.foundation.registry import protocols

        tags = _tags()
        self.assertIn('register_sctp_chunk', tags)  # the pattern still matches the module
        for name, paths in tags.items():
            self.assertIn(name, protocols.__all__)
            for path in paths:
                with self.subTest(wrapper=name, map=path):
                    self.assertIsInstance(_resolve(path), dict)

    def test_every_map_has_a_wrapper_or_an_excuse(self) -> None:
        tagged = {path for paths in _tags().values() for path in paths}
        maps = _maps()
        self.assertEqual(sorted(set(maps) - tagged - set(EXCUSED)), [],
                         'a registry map has no register_* wrapper tagged "# NOTE: <map>"')
        self.assertEqual(sorted(set(EXCUSED) & tagged), [], 'an excused map has a wrapper now')
        self.assertEqual(sorted(set(EXCUSED) - set(maps)), [], 'an excused map no longer exists')

    def test_every_map_owner_has_its_classmethod_or_inherits_a_typed_one(self) -> None:
        maps = _maps()
        self.assertIn('pcapkit.protocols.transport.tcp.TCP.__proto__', maps)  # the walk still finds them
        missing = []
        for path in sorted(set(maps) - set(EXCUSED)):
            owner, name = maps[path], _classmethod_name(path)
            with self.subTest(map=path):
                if name in vars(owner):
                    self.assertNotIn(path, INHERITED, f'{owner.__name__} defines its own {name} now')
                elif path in INHERITED:
                    inherited = _resolve(INHERITED[path][0])
                    self.assertIs(getattr(owner, name).__func__, inherited.__func__)
                else:
                    missing.append(f'{owner.__name__}.{name}')
        self.assertEqual(missing, [], 'a map owner inherits a register* classmethod INHERITED does not name')
        self.assertEqual(sorted(set(INHERITED) - set(maps)), [], 'an inherited map no longer exists')
        self.assertEqual(sorted(set(INHERITED) & set(EXCUSED)), [], 'a map is both inherited and excused')

    def test_ipx_loopback_and_sctp_wrappers_write_the_owning_class_map(self) -> None:
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.protocols.transport.udp import UDP

        # NCP is Packet Type 17, which is UDP's IP protocol number too.
        cases = ((registry.register_ipx, IPX, Internet, Packet.NCP),
                 (registry.register_ipx, IPX, Internet, 4),
                 (registry.register_loopback, Loopback, Link, 2))
        for func, owner, parent, code in cases:
            parent_before = dict(parent.__proto__)
            with self.subTest(func=func.__name__, code=code), mock.patch.dict(owner.__proto__), \
                    warnings.catch_warnings():
                warnings.simplefilter('ignore')
                func(code, UDP)
                self.assertIs(owner.__proto__[code], UDP)
                self.assertEqual(dict(parent.__proto__), parent_before)

        cases = (
            (registry.register_sctp_chunk, Chunk.Cookie_Acknowledgement, '__chunk__', 'abort'),
            (registry.register_sctp_parameter, Parameter.Heartbeat_Info, '__parameter__', 'cookie'),
            (registry.register_sctp_cause, CauseCode.Stale_Cookie, '__cause__', 'no_user_data'),
        )
        for func, code, table, meth in cases:
            with self.subTest(func=func.__name__), mock.patch.dict(getattr(SCTP, table)), \
                    warnings.catch_warnings():
                warnings.simplefilter('ignore')
                func(code, meth)
                self.assertEqual(getattr(SCTP, table)[code], meth)

    def test_ipx_and_loopback_classmethods_warn_in_their_own_key_terms(self) -> None:
        """Each overrides its parent's, whose warning names an IP protocol or EtherType."""
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.udp import UDP
        from pcapkit.utilities.warnings import RegistryWarning

        for owner, code, term in ((IPX, Packet.NCP, 'packet type'), (Loopback, 2, 'address family')):
            with self.subTest(owner=owner.__name__), mock.patch.dict(owner.__proto__):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    owner.register(code, UDP)
                with self.assertWarnsRegex(RegistryWarning,
                                           '^' + re.escape(f'{term} {code} already registered, overwriting ')):
                    owner.register(code, Raw)
                self.assertIs(owner.__proto__[code], Raw)
                with warnings.catch_warnings():
                    warnings.simplefilter('error')
                    owner.register(code, Raw)  # handing back the stored entry is silent
                self.assertIs(owner.__proto__[code], Raw)

    def test_register_ipx_and_register_loopback_dispatch_the_payload(self) -> None:
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.protocols import __proto__ as names
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.protocols.transport.udp import UDP

        udp = bytes.fromhex('0035' '0035' '0008' '0000')
        ipx = b'\xff\xff' + (30 + len(udp)).to_bytes(2, 'big') + b'\x00\x11' + bytes(24) + udp
        # Address family 99, which nothing ships, written as LINKTYPE_NULL does.
        loopback = (99).to_bytes(4, 'little') + udp
        cases = ((registry.register_ipx, IPX, Packet.NCP, ipx),
                 (registry.register_loopback, Loopback, 99, loopback))
        for func, owner, code, packet in cases:
            with self.subTest(func=func.__name__), mock.patch.dict(owner.__proto__), \
                    mock.patch.dict(names), mock.patch.dict(registry._CODE_LEASES), \
                    mock.patch.dict(registry._NAME_LEASES), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                func(code, 'pcapkit.protocols.transport.udp', 'UDP')
                parsed = owner(io.BytesIO(packet), len(packet))
            self.assertIs(type(parsed.payload), UDP)


if __name__ == '__main__':
    unittest.main()
