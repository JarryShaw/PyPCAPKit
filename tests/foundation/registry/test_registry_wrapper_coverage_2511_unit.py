# -*- coding: utf-8 -*-
"""Every class-level registry map has its registration wrapper. C.f. #2511.

The owner ruled that each dispatch map a protocol class keeps -- ``__proto__``,
``__option__``, ``__chunk__`` and the rest -- is written through a public
``register_*`` wrapper in :mod:`pcapkit.foundation.registry.protocols`, which
validates the code and the target before calling the owning class's own
``register`` classmethod. Each wrapper names the map it writes in a
``# NOTE: <map path>`` line directly above its ``def``, and that tag is what this
module reads.

The maps are found by walking every :class:`~pcapkit.protocols.protocol.ProtocolBase`
descendant for a dunder :class:`dict` in its own :func:`vars`, so a map added
tomorrow fails here until it has a wrapper or an entry in ``EXCUSED``. The
table is checked in both directions: an excused map that gains a wrapper, or
stops existing, fails too.

The behaviour of the wrappers #2511 added is pinned at the end: each writes the
owning class's map, and ``register_ipx`` dispatches a parse to what it
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
    'pcapkit.protocols.link.frad.FRAD.__proto__': 'link-layer wrapper owned by #2510',
    'pcapkit.protocols.link.netlink.Netlink.__proto__': 'link-layer wrapper owned by #2510',
    'pcapkit.protocols.link.loopback.Loopback.__proto__':
        'link-layer section owned by #2510; keyed by a bare address family with no enum to check',
}

#: A wrapper's tag: one or more map paths on the comment line above its ``def``.
TAG = re.compile(r'^# NOTE: (?P<paths>\S.*)\ndef (?P<name>register_\w+)\(', re.MULTILINE)


def _import_protocols() -> None:
    """Import every shipped protocol module, so every class is a subclass by now."""
    import pcapkit.protocols as package

    for info in pkgutil.walk_packages(package.__path__, 'pcapkit.protocols.'):
        if 'NotImplemented' not in info.name:
            importlib.import_module(info.name)


def _maps() -> 'dict[str, dict]':
    """Every dunder :class:`dict` a protocol class holds in its own :func:`vars`, by path."""
    from pcapkit.protocols.protocol import ProtocolBase

    _import_protocols()
    found = {}  # type: dict[str, dict]
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
                found[f'{klass.__module__}.{klass.__qualname__}.{name}'] = value
    return found


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

    def test_ipx_and_sctp_wrappers_write_the_owning_class_map(self) -> None:
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.protocols.transport.udp import UDP

        # NCP is Packet Type 17, which is UDP's IP protocol number too.
        shipped = Internet.__proto__[Packet.NCP]
        with mock.patch.dict(IPX.__proto__), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            registry.register_ipx(Packet.NCP, UDP)
            self.assertIs(IPX.__proto__[Packet.NCP], UDP)
            self.assertIs(Internet.__proto__[Packet.NCP], shipped)

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

    def test_register_ipx_dispatches_the_payload(self) -> None:
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.protocols import __proto__ as names
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.transport.udp import UDP

        udp = bytes.fromhex('0035' '0035' '0008' '0000')
        packet = b'\xff\xff' + (30 + len(udp)).to_bytes(2, 'big') + b'\x00\x11' + bytes(24) + udp
        with mock.patch.dict(IPX.__proto__), mock.patch.dict(names), \
                mock.patch.dict(registry._CODE_LEASES), mock.patch.dict(registry._NAME_LEASES), \
                warnings.catch_warnings():
            warnings.simplefilter('ignore')
            registry.register_ipx(Packet.NCP, 'pcapkit.protocols.transport.udp', 'UDP')
            parsed = IPX(io.BytesIO(packet), len(packet))
        self.assertIs(type(parsed.payload), UDP)


if __name__ == '__main__':
    unittest.main()
