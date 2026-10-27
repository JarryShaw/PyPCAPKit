# -*- coding: utf-8 -*-
"""Every toolkit adapter message leads with its engine's name. C.f. #2304.

The adapters under :mod:`pcapkit.toolkit` put the engine name inside the
sentence -- ``IPv4 reassembly is not supported by the pcap-ct engine: ...``,
``invalid PyShark boolean field tcp.flags_fin: ...`` -- rather than leading with
it as the ``<prefix>: <lowercase description>: ... {value!r}`` form asks for
(#2232, #2257), and spelled it their own way rather than the way the engine's
own ``__engine_name__`` does: ``pcap-ct`` where the engine is ``PCAP_CT``.

Each message is pinned whole below, and each prefix is checked against the
engine class's ``__engine_name__`` rather than against a literal, so a prefix
typed by hand here or there regresses even when the two happen to agree today.

Nothing here imports ``pcap``, ``pcapfile``, ``pyshark`` or ``scapy``: every
message comes off a pure adapter function, or -- for the one warning Scapy
emits on import -- off an import with the package mocked away. So the whole
module runs with no third-party engine installed, which is also why it pins the
messages here rather than only in the per-engine modules, three of which skip
without their backend.

"""
from __future__ import annotations

import builtins
import importlib
import importlib.util
import types
import unittest
import warnings
from unittest import mock

from tests._support import purge_modules, reimport_once_per_class
from tests.toolkit.test_pypcapfile_unit import ipv6_frame, make_packet
from tests.toolkit.test_pyshark_unit import FakePySharkPacket, LayerField

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The suffix every ``pcap``-binding refusal carries, by engine module name.
NO_DISSECTION = {
    'pcap_ct': ("'pcap-ct' is a libpcap binding and performs no protocol dissection, so there "
                'is no protocol layer to read'),
    'pypcap': ("'pypcap' is a libpcap binding and performs no protocol dissection, so there "
               'is no protocol layer to read'),
}


def engine_name(module: 'str') -> 'str':
    """``__engine_name__`` of the engine class driving :mod:`pcapkit.toolkit.{module}`."""
    from pcapkit.foundation import engines

    #: Engine class per toolkit module. Spelled out rather than guessed from the
    #: module name, since ``PCAP_CT`` is neither ``Pcap_Ct`` nor ``PCAP-CT``.
    classes = {
        'pcap_ct': engines.PCAP_CT, 'pypcap': engines.PyPCAP,
        'pypcapfile': engines.PyPCAPFile, 'pyshark': engines.PyShark,
        'scapy': engines.Scapy,
    }
    return classes[module].__engine_name__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineNamePrefixTests(unittest.TestCase):
    """Each message is pinned whole, and its prefix is the engine's own name."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertPrefixed(self, module: 'str', message: 'str') -> 'None':
        """``message`` leads with :mod:`pcapkit.toolkit.{module}`'s ``__engine_name__``."""
        prefix = '%s: ' % engine_name(module)
        self.assertTrue(message.startswith(prefix), '%r does not lead with %r' % (message, prefix))

    def test_the_pcap_bindings_refuse_under_their_own_name(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.utilities.exceptions import UnsupportedCall

        for module in ('pcap_ct', 'pypcap'):
            toolkit = importlib.import_module('pcapkit.toolkit.%s' % module)
            suffix = NO_DISSECTION[module]
            for name, call, description in (
                ('ipv4_reassembly', lambda t=toolkit: t.ipv4_reassembly(b'raw', count=1),
                 'IPv4 reassembly is not supported'),
                ('ipv6_reassembly', lambda t=toolkit: t.ipv6_reassembly(b'raw', count=1),
                 'IPv6 reassembly is not supported'),
                ('tcp_reassembly', lambda t=toolkit: t.tcp_reassembly(b'raw', count=1),
                 'TCP reassembly is not supported'),
                ('tcp_traceflow', lambda t=toolkit: t.tcp_traceflow(
                    b'raw', 1.0, data_link=LinkType.ETHERNET, count=1),
                 'TCP flow tracing is not supported'),
            ):
                with self.subTest(module=module, function=name):
                    with self.assertRaises(UnsupportedCall) as caught:
                        call()
                    message = str(caught.exception)
                    self.assertEqual(message, '%s: %s: %s' % (engine_name(module), description,
                                                              suffix))
                    self.assertPrefixed(module, message)

    def test_pcap_ct_is_named_the_way_its_engine_names_itself(self) -> None:
        """The reported regression: the engine is ``PCAP_CT``, not ``pcap-ct``."""
        from pcapkit.toolkit.pcap_ct import ipv4_reassembly
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall) as caught:
            ipv4_reassembly(b'raw', count=1)
        self.assertEqual(str(caught.exception).split(':')[0], 'PCAP_CT')
        self.assertEqual(engine_name('pcap_ct'), 'PCAP_CT')

    def test_pypcapfile_address_rejections(self) -> None:
        from pcapkit.toolkit import pypcapfile as toolkit
        from pcapkit.utilities.exceptions import ProtocolError

        for parse, label, value in (
            (toolkit._parse_ipv4_address, 'IPv4 address', 5),
            (toolkit._parse_ipv4_address, 'IPv4 address', None),
            (toolkit._parse_ipv4_address, 'IPv4 address', b'nope!'),
            (toolkit._parse_ipv4_address, 'IPv4 address', b'\xff\xfe no ascii'),
            (toolkit._parse_mac_address, 'MAC address', 5),
            (toolkit._parse_mac_address, 'MAC address', None),
            (toolkit._parse_mac_address, 'MAC address', b'\xff\xfe no ascii'),
        ):
            with self.subTest(parse=parse.__name__, value=value):
                with self.assertRaises(ProtocolError) as caught:
                    parse(value)
                self.assertEqual(str(caught.exception),
                                 'PyPCAPFile: invalid %s: %r' % (label, value))
                self.assertPrefixed('pypcapfile', str(caught.exception))

    def test_pypcapfile_ipv6_reassembly_refusal(self) -> None:
        from pcapkit.toolkit.pypcapfile import ipv6_reassembly
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall) as caught:
            ipv6_reassembly(make_packet(ipv6_frame(6)), count=1)
        self.assertEqual(str(caught.exception),
                         "PyPCAPFile: IPv6 reassembly is not supported: 'pypcapfile' has no IPv6 "
                         'decoder, so no IPv6 fragment header can be read')
        self.assertPrefixed('pypcapfile', str(caught.exception))

    def test_pypcapfile_tcp_over_ipv6_warning(self) -> None:
        from pcapkit.toolkit.pypcapfile import tcp_reassembly
        from pcapkit.utilities.warnings import AttributeWarning

        header = [types.SimpleNamespace(ns_resolution=False)]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            self.assertIsNone(tcp_reassembly(make_packet(ipv6_frame(6), header=header), count=7))
        messages = [str(item.message) for item in caught
                    if issubclass(item.category, AttributeWarning)]
        self.assertEqual(messages, [
            'PyPCAPFile: frame 7: TCP over IPv6 is left out of TCP reassembly and flow tracing, '
            "as 'pypcapfile' has no IPv6 decoder; later such frames of this capture are left out "
            'without another warning'])
        self.assertPrefixed('pypcapfile', messages[0])

    def test_pyshark_field_rejections(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as caught:
            toolkit._parse_flag(LayerField('x'), 'tcp.flags_fin')
        self.assertEqual(str(caught.exception),
                         "PyShark: invalid boolean field tcp.flags_fin: 'x'")
        self.assertPrefixed('pyshark', str(caught.exception))

        with self.assertRaises(ProtocolError) as caught:
            toolkit._parse_epoch(LayerField('Jul 14, 2017'))
        self.assertEqual(str(caught.exception),
                         "PyShark: invalid frame.time_epoch: 'Jul 14, 2017'")
        self.assertPrefixed('pyshark', str(caught.exception))

    def test_pyshark_missing_frame_layer(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.utilities.exceptions import ProtocolError

        packet = FakePySharkPacket(comment='a packet comment')
        packet.layers = packet.layers[1:]
        with self.assertRaises(ProtocolError) as caught:
            toolkit.tcp_traceflow(packet)
        self.assertEqual(str(caught.exception), 'PyShark: packet 12 has no frame layer')
        self.assertPrefixed('pyshark', str(caught.exception))

    def test_scapy_missing_dependency_warning(self) -> None:
        """The import-time warning, with |scapy|_ mocked away so it fires either way."""
        from pcapkit.utilities.warnings import ScapyWarning

        # Put a real import back afterwards, as
        # ``test_scapy_unit.test_import_without_scapy_sets_none_and_warns``
        # does: cleanups run last-in first-out, so the Scapy-less copy is
        # purged and then re-imported (GitHub issue #1065).
        self.addCleanup(importlib.import_module, 'pcapkit.toolkit.scapy')
        self.addCleanup(purge_modules, ['pcapkit.toolkit.scapy'])
        purge_modules(['pcapkit.toolkit.scapy'])
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):  # type: ignore[no-untyped-def]
            if name == 'scapy':
                raise ModuleNotFoundError("No module named 'scapy'")
            return real_import(name, *args, **kwargs)

        with mock.patch('builtins.__import__', side_effect=fake_import), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            module = importlib.import_module('pcapkit.toolkit.scapy')

        self.assertIsNone(module.scapy)
        messages = [str(item.message) for item in caught
                    if issubclass(item.category, ScapyWarning)]
        self.assertEqual(messages, ["Scapy: dependency package 'scapy' not found"])
        self.assertPrefixed('scapy', messages[0])

    def test_every_prefix_is_read_off_the_engine_class(self) -> None:
        """No adapter spells its engine's name itself."""
        for module in ('pcap_ct', 'pypcap', 'pypcapfile', 'pyshark', 'scapy'):
            with self.subTest(module=module):
                toolkit = importlib.import_module('pcapkit.toolkit.%s' % module)
                self.assertEqual(toolkit._ENGINE, engine_name(module))


if __name__ == '__main__':
    unittest.main()
