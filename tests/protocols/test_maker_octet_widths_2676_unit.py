# -*- coding: utf-8 -*-
"""The makers refuse a fixed-size octet field, or a timestamp count, that does not fit.

GitHub issue #2676: a schema field of a fixed number of octets packs as
:mod:`struct`'s ``s`` format does, so a maker that hands it a caller's octets
unchecked pads a short value and cuts a long one, as the CALIPSO checksum did
with 300 octets. Each maker routes such a value through
:meth:`~pcapkit.protocols.protocol.Protocol._make_octets`, which raises a
:exc:`~pcapkit.utilities.exceptions.ProtocolError` for any other width, as #2617
has every out-of-range value raise rather than be masked.

* :class:`SweepTests` finds every fixed-size octet field a maker writes, from the
  schema and protocol sources, so a new one is held to the rule without a row.
* The protocol classes check each field's refusal, and that its widest value
  builds at the offset its specification gives and survives parse -> rebuild.
  The MH and HIP rows come from the maker signatures.
* :class:`IPv4TimestampTests` covers the timestamp option's slot count, bounded by
  the option's 40 octets, and its default, derived from the timestamps' form.
* :class:`CapturedOctetTests` checks that a capture cut inside a reserved field
  still rebuilds as captured, and that a model of the wrong width is refused.

``protocol.rst``'s entries for the value helpers are pinned in
:file:`tests/project/test_docs_value_helpers_2676_unit.py`.

Every case builds its own octets in memory and reads no capture.

"""

import ast
import inspect
import io
import pathlib
import unittest
import warnings

from tests._support import reimport_once_per_class

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Fixed-size octet fields a maker writes without ``_make_octets``, and why.
EXEMPT = {
    ('pcapkit/protocols/application/httpv2.py', '_make_http_ping', 'data'):
        'its own length check refuses any width but eight',
    ('pcapkit/protocols/internet/mh.py', '_make_opt_mn_lla_iid', 'iid'):
        'its own length check refuses any width but eight',
    ('pcapkit/protocols/link/linux_sll1.py', 'make', 'link_addr'):
        '_validate_link_addr refuses more than eight octets and zero-fills a shorter '
        'address, whose length link_addr_length carries',
    ('pcapkit/protocols/link/linux_sll2.py', 'make', 'link_addr'):
        '_validate_link_addr refuses more than eight octets and zero-fills a shorter '
        'address, whose length link_addr_length carries',
    ('pcapkit/protocols/link/radiotap.py', '_make_tlv_data', 'oui'):
        '_make_vendor_data refuses any width but the field\'s',
    ('pcapkit/protocols/link/radiotap.py', '_make_vendor_namespace', 'oui'):
        '_make_vendor_data refuses any width but the field\'s',
    ('pcapkit/protocols/misc/pcap/header.py', 'make', 'magic_number'):
        'made from the byte order and resolution flags, not given as octets',
}

#: Helpers whose result is exactly the width they are given.
CHECKED = ('_make_octets', '_make_mac_addr', '_make_pack')


def _base_name(node: 'ast.expr') -> 'str | None':
    """The bare name a base class is written with, its subscript dropped: ``EnumSchema[X]`` is ``EnumSchema``."""
    if isinstance(node, ast.Subscript):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _schema_fields() -> 'dict[tuple[str, str], tuple[dict[str, int | None], list[tuple[str, str]]]]':
    """``{(module, class): ({field: fixed size or None}, [base (module, class)])}`` for every schema."""
    classes = {}  # type: dict[tuple[str, str], tuple[dict[str, int | None], list[tuple[str, str]]]]
    for path in sorted((ROOT / 'pcapkit/protocols/schema').rglob('*.py')):
        module = '.'.join(path.relative_to(ROOT).with_suffix('').parts)
        tree = ast.parse(path.read_text(encoding='utf-8'))
        names = {node.name: (module, node.name) for node in tree.body if isinstance(node, ast.ClassDef)}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('pcapkit.protocols.schema'):
                names.update({alias.asname or alias.name: (node.module, alias.name) for alias in node.names})
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            fields = {}  # type: dict[str, int | None]
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    size = None
                    call = stmt.value
                    if isinstance(call, ast.Call) and getattr(call.func, 'id', None) in ('BytesField', 'PaddingField'):
                        for kw in call.keywords:
                            if kw.arg == 'length' and isinstance(kw.value, ast.Constant) \
                                    and isinstance(kw.value.value, int):
                                size = kw.value.value
                    fields[stmt.target.id] = size
            bases = [names[base] for base in map(_base_name, node.bases) if base in names]
            classes[(module, node.name)] = (fields, bases)
    return classes


def _fixed_size(classes: 'dict', key: 'tuple[str, str]', field: 'str') -> 'int | None':
    """The fixed width of ``field`` on schema ``key``, from the nearest class that declares it."""
    if key not in classes:
        return None
    fields, bases = classes[key]
    if field in fields:
        return fields[field]
    for base in bases:
        size = _fixed_size(classes, base, field)
        if size is not None:
            return size
    return None


def _checked(node: 'ast.expr', size: 'int', assigned: 'dict[str, list[tuple[int, ast.expr]]]', line: 'int') -> 'bool':
    """Whether ``node`` is exactly ``size`` octets by construction."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, bytes) and len(node.value) == size
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Attribute) and node.func.attr in CHECKED
    if isinstance(node, ast.IfExp):
        return _checked(node.body, size, assigned, line) and _checked(node.orelse, size, assigned, line)
    if isinstance(node, ast.Name):
        before = [value for lineno, value in assigned.get(node.id, []) if lineno < line]
        return bool(before) and _checked(before[-1], size, assigned, line)
    return False


def unchecked_octet_fields() -> 'tuple[set[tuple[str, str, str]], set[tuple[str, str, str]]]':
    """Every fixed-size octet field a maker writes, and those it writes unchecked: ``(path, maker, field)``."""
    classes = _schema_fields()
    found, unchecked = set(), set()
    for path in sorted((ROOT / 'pcapkit/protocols').rglob('*.py')):
        if 'schema' in path.parts or 'data' in path.parts:
            continue
        rel = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding='utf-8'))
        imports = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('pcapkit.protocols.schema'):
                imports.update({alias.asname or alias.name: (node.module, alias.name) for alias in node.names})
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef) or not (func.name == 'make' or func.name.startswith('_make')):
                continue
            assigned = {}  # type: dict[str, list[tuple[int, ast.expr]]]
            for node in ast.walk(func):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assigned.setdefault(target.id, []).append((node.lineno, node.value))
            for value in assigned.values():
                value.sort(key=lambda item: item[0])
            for node in ast.walk(func):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in imports):
                    continue
                for kw in node.keywords:
                    size = _fixed_size(classes, imports[node.func.id], kw.arg) if kw.arg else None
                    if size is None:
                        continue
                    found.add((rel, func.name, kw.arg))
                    if not _checked(kw.value, size, assigned, node.lineno):
                        unchecked.add((rel, func.name, kw.arg))
    return found, unchecked


def _octet_arguments(func: 'object', exclude: 'set[str]') -> 'list[tuple[str, int]]':
    """``(argument, width)`` for each keyword of ``func`` that defaults to fixed-size octets."""
    return [(param.name, len(param.default))
            for param in inspect.signature(func).parameters.values()  # type: ignore[arg-type]
            if str(param.annotation) == 'bytes' and isinstance(param.default, bytes) and param.default
            and param.name not in exclude]


class _Case(unittest.TestCase):
    """Fresh :mod:`pcapkit` once per class, and the octet-width checks."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertWidth(self, alias: 'str', name: 'str', size: 'int', build: 'object', rebuild: 'object',
                    offset: 'int | None' = None, where: 'str' = '') -> None:
        """``build(octets)`` refuses one octet too few or too many, and builds and rebuilds ``size`` of ``0xFF``."""
        from pcapkit.utilities.exceptions import ProtocolError

        unit = 'octet' if size == 1 else 'octets'
        for value in (b'\xff' * (size - 1), b'\xff' * (size + 1)):
            with self.subTest(where=where, field=name, width=len(value)):
                with self.assertRaises(ProtocolError) as caught:
                    build(value)  # type: ignore[operator]
                self.assertEqual(str(caught.exception), f'{alias}: invalid {name}: must be {size} {unit}, '
                                                        f'not {value!r}')
        with self.subTest(where=where, field=name, width=size):
            data = build(b'\xff' * size)  # type: ignore[operator]
            if offset is None:
                self.assertIn(b'\xff' * size, data)
            else:
                self.assertEqual(data[offset:offset + size], b'\xff' * size)
            self.assertEqual(rebuild(data), data)  # type: ignore[operator]


class SweepTests(unittest.TestCase):
    """Every fixed-size octet field a maker writes is checked for its width."""

    def test_every_fixed_octet_field_is_checked(self) -> None:
        # An exemption names a field the sweep finds unchecked, so a fix
        # deletes its row.
        found, unchecked = unchecked_octet_fields()
        self.assertIn(('pcapkit/protocols/internet/hopopt.py', '_make_opt_calipso', 'checksum'), found)
        self.assertEqual(sorted(unchecked - set(EXEMPT)), [])
        self.assertEqual(sorted(set(EXEMPT) - unchecked), [])


class IPv6OptionTests(_Case):
    """HOPOPT and IPv6-Opts, which share their option makers."""

    def _classes(self) -> 'dict[str, type]':
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        return {'HOPOPT': HOPOPT, 'IPv6-Opts': IPv6_Opts}

    def test_calipso_checksum(self) -> None:
        # RFC 5570 section 5.1: type, length, the 32-bit DOI, Cmpt Length and
        # Sens Level, then the 16-bit checksum, after the 2-octet header.
        from pcapkit.const.ipv6.option import Option

        for alias, cls in self._classes().items():
            self.assertWidth(alias, 'CALIPSO checksum', 2,
                             lambda value, cls=cls: cls(next=59, options=[(Option.CALIPSO, {'checksum': value})]).data,
                             lambda data, cls=cls: cls.from_data(cls(data, len(data), extension=True).info).data,
                             offset=10)

    def test_quick_start_report_not_used_octet(self) -> None:
        # RFC 4782 section 3.1, figure 4, which section 3.2 keeps for IPv6: the
        # function and rate, then the Not Used octet.
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.qs_function import QSFunction

        for alias, cls in self._classes().items():
            self.assertWidth(alias, 'Quick-Start not-used octet', 1,
                             lambda value, cls=cls: cls(next=59, options=[(Option.Quick_Start, {
                                 'func': QSFunction.Report_of_Approved_Rate, 'unused': value})]).data,
                             lambda data, cls=cls: cls.from_data(cls(data, len(data), extension=True).info).data,
                             offset=5)


class IPv4TimestampTests(_Case):
    """The timestamp option's slot count, and IPv4's header checksum."""

    def _make(self, **args: 'object') -> 'bytes':
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        return IPv4(protocol=253, options=[(OptionNumber.TS, args)]).data

    def _rebuild(self, data: 'bytes') -> 'bytes':
        from pcapkit.protocols.internet.ipv4 import IPv4

        return IPv4.from_data(IPv4(data).info).data

    def test_count_is_what_the_option_holds(self) -> None:
        # RFC 791 section 3.1: the option is 40 octets at most, so nine 4-octet
        # timestamps, or four 8-octet address and timestamp pairs. A count
        # past that is refused; the widest fills the option, and the default
        # is five timestamps, or four pairs. The option's length octet
        # follows its type, at octet 21 of the header.
        from pcapkit.utilities.exceptions import ProtocolError

        for timestamp, counts in (([], 10), ({}, 5), ([], 1 << 64), ({}, 9)):
            with self.subTest(timestamp=type(timestamp).__name__, counts=counts):
                with self.assertRaises(ProtocolError) as caught:
                    self._make(counts=counts, timestamp=timestamp)
                self.assertEqual(str(caught.exception), f'IPv4: invalid timestamp count: {counts}')
        for timestamp, counts, length in (([], 9, 40), ({}, 4, 36), ([], None, 24), ({}, None, 36),
                                          (None, None, 24)):
            with self.subTest(timestamp=type(timestamp).__name__, counts=counts):
                data = self._make(timestamp=timestamp) if counts is None else \
                    self._make(counts=counts, timestamp=timestamp)
                self.assertEqual(data[21], length)
                self.assertEqual(self._rebuild(data), data)

    def test_header_checksum(self) -> None:
        # RFC 791 section 3.1: the Header Checksum is octets 10 and 11.
        from pcapkit.protocols.internet.ipv4 import IPv4

        self.assertWidth('IPv4', 'checksum', 2, lambda value: IPv4(protocol=253, checksum=value).data,
                         self._rebuild, offset=10)


class MHTests(_Case):
    """MH's header, message, option and sub-option makers."""

    #: Octet arguments with a non-empty default that are not of a fixed size, and why.
    VARIABLE = {
        # The message data of an Experimental Mobility Header, of any length.
        '_make_msg_emh.data',
    }

    #: Sub-options and attributes, which no maker signature declares:
    #: ``(option, list argument, entry code, width)``; the entry takes ``reserved``.
    NESTED = (
        ('Flow_Identification_Mobility_Option', 'suboptions', 'Traffic_Selector', 1),
        ('Flow_Identification_Mobility_Option', 'suboptions', 'Flow_Binding_Action', 1),
        ('Flow_Identification_Mobility_Option', 'suboptions', 'Target_Care_of_Address', 2),
        ('Access_Network_Identifier', 'suboptions', 'Civic_Location', 1),
        ('Quality_of_Service', 'attributes', 'Guaranteed_DL_Bit_Rate', 2),
        ('Quality_of_Service', 'attributes', 'Allocation_Retention_Priority', 1),
        ('Quality_of_Service', 'attributes', 'QoS_Traffic_Selector', 1),
        ('Quality_of_Service', 'attributes', 'QoS_Vendor_Specific_Attribute', 2),
    )

    def _make(self, *options: 'tuple[str, dict[str, object]]', **kwargs: 'object') -> 'bytes':
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH

        return bytes(MH(next=59, type=Packet.Binding_Refresh_Request,
                        data={'options': [(Option[name], args) for name, args in options]}, **kwargs))

    def _rebuild(self, data: 'bytes') -> 'bytes':
        from pcapkit.protocols.internet.mh import MH

        return MH.from_data(MH(io.BytesIO(data), len(data), extension=True).info).data

    def test_header_checksum(self) -> None:
        # RFC 6275 section 6.1.1: Checksum is octets 4 and 5.
        self.assertWidth('MH', 'checksum', 2, lambda value: self._make(chksum=value), self._rebuild, offset=4)

    def test_message_octets(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        packets = {name: code for code, name in MH.__message__.items() if isinstance(name, str)}
        swept = []
        for name in sorted(vars(MH)):
            if not name.startswith('_make_msg_'):
                continue
            for arg, size in _octet_arguments(getattr(MH, name), {a.split('.')[1] for a in self.VARIABLE
                                                                 if a.startswith(f'{name}.')}):
                swept.append(f'{name}.{arg}')
                code = packets[name[len('_make_msg_'):]]
                label = 'reserved octets' if arg == 'msg_reserved' else arg
                self.assertWidth('MH', label, size,
                                 lambda value, code=code, arg=arg: bytes(MH(next=59, type=code, data={arg: value})),
                                 self._rebuild, where=f'{name}.{arg}')
        self.assertIn('_make_msg_hot.token', swept)

    def test_option_octets(self) -> None:
        # The interface identifier is a fixed 8 octets (RFC 5949),
        # which its maker refuses at any other width in a message of its own.
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        swept = []
        for code, name in sorted(MH.__option__.items()):
            maker = f'_make_opt_{name}'
            if not isinstance(name, str) or not hasattr(MH, maker) or maker in swept:
                continue
            swept.append(maker)
            for arg, size in _octet_arguments(getattr(MH, maker), set()):
                label = {'reserved': 'reserved octets'}.get(arg, arg)
                if maker == '_make_opt_mn_lla_iid' and arg == 'iid':
                    for iid in (bytes(7), bytes(9)):
                        with self.subTest(where=f'{maker}.{arg}', width=len(iid)):
                            with self.assertRaisesRegex(ProtocolError, 'invalid interface identifier'):
                                self._make((Option(code).name, {arg: iid}))
                    continue
                self.assertWidth('MH', label, size,
                                 lambda value, code=code, arg=arg: self._make((Option(code).name, {arg: value})),
                                 self._rebuild, where=f'{maker}.{arg}')
        self.assertIn('_make_opt_ct', swept)

    def test_nested_octets(self) -> None:
        from pcapkit.const.mh.ani_suboption import ANISuboption
        from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption
        from pcapkit.const.mh.qos_attribute import QoSAttribute

        enums = (FlowIDSuboption, ANISuboption, QoSAttribute)
        for option, key, entry, size in self.NESTED:
            enum = next(e for e in enums if entry in e.__members__ and e.__name__ != 'Option')
            with self.subTest(option=option, entry=entry):
                self.assertWidth('MH', 'reserved octets', size,
                                 lambda value, option=option, key=key, entry=enum[entry]: self._make(
                                     (option, {key: [(entry, {'reserved': value})]})),
                                 self._rebuild)


class HIPTests(_Case):
    """HIP's header and parameter makers."""

    #: Arguments a parameter needs to build at all, by maker suffix.
    BASE = {'puzzle': {'lifetime': 1}}

    def _rebuild(self, data: 'bytes') -> 'bytes':
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.warnings import ProtocolWarning

        # An ENCRYPTED parameter with no HIP_CIPHER beside it warns on read.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', ProtocolWarning)
            return HIP.from_data(HIP(data).info).data

    def test_header_checksum(self) -> None:
        # RFC 7401 section 5.1: Checksum is octets 4 and 5.
        from pcapkit.protocols.internet.hip import HIP

        self.assertWidth('HIPv2', 'checksum', 2, lambda value: bytes(HIP(version=2, checksum=value)),
                         self._rebuild, offset=4)

    def test_parameter_octets(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        names = {'reserved': 'reserved octets', 'payload': 'payload data'}
        swept = []
        for code, name in sorted(HIP.__parameter__.items()):
            maker = f'_make_param_{name}'
            # ``R1_COUNTER`` has a HIPv1-only code as well as its HIPv2 one.
            if not isinstance(name, str) or not hasattr(HIP, maker) or maker in swept \
                    or code == Parameter.R1_Counter:
                continue
            swept.append(maker)
            for arg, size in _octet_arguments(getattr(HIP, maker), set()):
                label = names.get(arg, f'{name} {arg}')
                base = self.BASE.get(name, {})
                self.assertWidth('HIPv2', label, size,
                                 lambda value, code=code, arg=arg, base=base: bytes(HIP(
                                     version=2, parameters=[(code, {**base, arg: value})])),
                                 self._rebuild, where=f'{maker}.{arg}')
        self.assertIn('_make_param_payload_mic', swept)


class OtherMakerTests(_Case):
    """The other protocols the sweep reaches."""

    def test_icmp_checksum_and_unused_octets(self) -> None:
        # RFC 792 and RFC 4443 sections 2.1 and 3: the checksum is octets 2 and
        # 3, and the unused octets follow it, after a pointer octet for
        # Parameter Problem. ICMPv4 takes RFC 792's name, ICMP, as its alias.
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        for alias, cls, rows in (('ICMP', ICMPv4, ((3, 4, 4), (11, 4, 4), (12, 3, 5))),
                                 ('ICMPv6', ICMPv6, ((1, 4, 4), (3, 4, 4)))):
            rebuild = (lambda data, cls=cls: cls.from_data(cls(data).info).data)  # noqa: E731
            self.assertWidth(alias, 'checksum', 2, lambda value, cls=cls: cls(type=8 if cls is ICMPv4 else 128,
                                                                             checksum=value).data,
                             rebuild, offset=2)
            for kind, size, offset in rows:
                with self.subTest(protocol=alias, type=kind):
                    self.assertWidth(alias, 'unused octets', size,
                                     lambda value, cls=cls, kind=kind: cls(type=kind, body={'unused': value}).data,
                                     rebuild, offset=offset)

    def test_igmp_checksum_and_reserved(self) -> None:
        # RFC 2236 section 2 and RFC 3376 section 4.2: the checksum is octets 2
        # and 3, and a version 3 report's second reserved field octets 4 and 5.
        from pcapkit.const.igmp.type import Type
        from pcapkit.protocols.internet.igmpv2 import IGMPv2
        from pcapkit.protocols.internet.igmpv3 import IGMPv3

        self.assertWidth('IGMPv2', 'checksum', 2,
                         lambda value: IGMPv2(type=Type.IGMP_Membership_Query, max_resp_time=1, checksum=value).data,
                         lambda data: IGMPv2.from_data(IGMPv2(data).info).data, offset=2)
        report = Type.IGMPv3_Membership_Report
        for arg, name, offset in (('checksum', 'checksum', 2), ('reserved_2', 'reserved_2', 4)):
            self.assertWidth('IGMPv3', name, 2, lambda value, arg=arg: IGMPv3(type=report, **{arg: value}).data,
                             lambda data: IGMPv3.from_data(IGMPv3(data).info).data, offset=offset)

    def test_ipv6_frag_and_route_reserved(self) -> None:
        # RFC 8200 sections 4.5 and 4.4, and RFC 6275 section 6.4: the reserved
        # octet follows Next Header; the reserved word follows Segments Left.
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        self.assertWidth('IPv6-Frag', 'reserved octet', 1,
                         lambda value: IPv6_Frag(next=59, reserved_octet=value).data,
                         lambda data: IPv6_Frag.from_data(IPv6_Frag(data, len(data), extension=True).info).data,
                         offset=1)
        for kind, data in ((0, {'ip': ['2001:db8::1']}), (2, {'ip': '2001:db8::1'})):
            with self.subTest(type=kind):
                self.assertWidth('IPv6-Route', 'reserved octets', 4,
                                 lambda value, kind=kind, data=data: IPv6_Route(
                                     next=59, type=kind, data={**data, 'reserved': value}).data,
                                 lambda octets: IPv6_Route.from_data(
                                     IPv6_Route(octets, len(octets), extension=True).info).data,
                                 offset=4)

    def test_ipx_checksum_and_addresses(self) -> None:
        # The IPX header: checksum at octet 0, the 12-octet destination and
        # source addresses at octets 6 and 18.
        from pcapkit.protocols.internet.ipx import IPX

        for arg, name, size, offset in (('chksum', 'checksum', 2, 0), ('dst', 'destination address', 12, 6),
                                        ('src', 'source address', 12, 18)):
            self.assertWidth('IPX', name, size, lambda value, arg=arg: IPX(**{arg: value}).data,
                             lambda data: IPX.from_data(IPX(data).info).data, offset=offset)

    def test_ospf_checksum_and_authentication_reserved(self) -> None:
        # RFC 2328 appendix A.3.1 and D.3: the checksum is octets 12 and 13;
        # cryptographic authentication opens with two reserved octets at 16.
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.protocols.application.ospf import OSPF

        rebuild = (lambda data: OSPF.from_data(OSPF(data).info).data)  # noqa: E731
        self.assertWidth('OSPF', 'checksum', 2, lambda value: OSPF(checksum=value).data, rebuild, offset=12)
        auth = {'key_id': 1, 'len': 16, 'seq': 1}
        self.assertWidth('OSPF', 'reserved octets', 2,
                         lambda value: OSPF(auth_type=Authentication.Cryptographic_authentication,
                                            auth_data={**auth, 'reserved': value}).data,
                         rebuild, offset=16)

    def test_pcapng_zigbee_keys(self) -> None:
        # The ZigBee NWK and APS Key Secrets Data open with a 16-octet key.
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        proto = PCAPNG.__new__(PCAPNG)
        for code, maker, arg, name in (
                (SecretsType.ZigBee_NWK_Key, proto._make_secrets_zigbee_nwk, 'nwk_key', '[ZigBee NWK Key] key'),
                (SecretsType.ZigBee_APS_Key, proto._make_secrets_zigbee_aps, 'aps_key', '[ZigBee APS Key] key')):
            with self.subTest(code=code):
                schema = type(maker(code))
                self.assertWidth('PCAP-NG', name, 16, lambda value, maker=maker, code=code, arg=arg:
                                 maker(code, **{arg: value}).pack(),
                                 lambda data, schema=schema: schema.unpack(data).pack(), offset=0)
                self.assertEqual(maker(code).pack()[:16], bytes(16))


class CapturedOctetTests(_Case):
    """A capture cut inside a reserved field rebuilds as captured; a model of the wrong width is refused.

    After a short read a padding field keeps only the octets present, where a
    byte field zero-fills to its width. So a maker zero-fills a short value
    from a model that records the short read (``__short_read__``), as the rest
    of the cut header is, and the rebuild cuts back to what was captured
    (#1458). Any other model's value is checked as a caller's is.
    """

    #: MH messages whose reserved octets no fixed field follows, so that no cut
    #: past them records a short read: the options area after them records none.
    NOTHING_AFTER = {'_make_msg_fna', '_make_msg_has', '_make_msg_sq'}

    #: MH messages whose cut inside the reserved octets does not parse, and why.
    UNPARSED = {
        '_make_msg_lri': 'a cut message reads its options area as zeros, which raises a FieldValueError',
        '_make_msg_upa': 'a cut message reads its options area as zeros, which raises a FieldValueError',
    }

    def _mh_messages(self) -> 'list[tuple[str, object, int]]':
        from pcapkit.protocols.internet.mh import MH

        packets = {name: code for code, name in MH.__message__.items() if isinstance(name, str)}
        rows = []
        for name in sorted(vars(MH)):
            if name.startswith('_make_msg_'):
                for arg, size in _octet_arguments(getattr(MH, name), set()):
                    if arg == 'msg_reserved':
                        rows.append((name, packets[name[len('_make_msg_'):]], size))
        return rows

    def _parse(self, cls: 'type', data: 'bytes', **kwargs: 'object') -> 'object':
        """The info of ``data`` parsed by ``cls``, the warning of a cut length kept quiet."""
        from pcapkit.utilities.warnings import SchemaWarning

        with warnings.catch_warnings():
            warnings.simplefilter('ignore', SchemaWarning)
            if kwargs:
                return cls(io.BytesIO(data), len(data), **kwargs).info  # type: ignore[call-arg]
            return cls(data).info  # type: ignore[call-arg]

    def assertCutRebuilds(self, cls: 'type', data: 'bytes', mark: 'bytes', **kwargs: 'object') -> None:
        """Every cut of ``data`` inside ``mark``, or just before it, rebuilds as the octets captured.

        The rebuild is made from the data model and from the :obj:`dict` its
        ``to_dict()`` gives, which ``from_data`` takes as well.
        """
        start = data.index(mark)
        for cut in range(max(start - 1, 1), start + len(mark)):
            with self.subTest(protocol=cls.__name__, cut=cut):
                part = data[:cut]
                info = self._parse(cls, part, **kwargs)
                self.assertIsNotNone(info.get('__short_read__'))  # type: ignore[attr-defined]
                self.assertEqual(cls.from_data(info).data, part)  # type: ignore[attr-defined]
                self.assertEqual(cls.from_data(info.to_dict()).data, part)  # type: ignore[attr-defined]

    def assertEditRefused(self, cls: 'type', data: 'bytes', mark: 'bytes', edit: 'object', message: 'str',
                          **kwargs: 'object') -> 'bool':
        """A capture cut past ``mark`` keeps it whole, so ``edit`` shortening it is refused with ``message``.

        The cut is the first past ``mark`` that records a short read; whether
        there was one is returned.
        """
        from pcapkit.utilities.exceptions import ProtocolError

        end = data.index(mark) + len(mark)
        cuts = [cut for cut in range(end + 1, len(data))
                if self._parse(cls, data[:cut], **kwargs).get('__short_read__') is not None]  # type: ignore[attr-defined]
        if not cuts:
            return False
        for value in sorted({mark[:-1], b''}, key=len):
            with self.subTest(protocol=cls.__name__, cut=cuts[0], width=len(value)):
                info = self._parse(cls, data[:cuts[0]], **kwargs)
                edit(info, value)  # type: ignore[operator]
                with self.assertRaises(ProtocolError) as caught:
                    cls.from_data(info)  # type: ignore[attr-defined]
                self.assertEqual(str(caught.exception), f'{message}, not {value!r}')
        return True

    def test_mh_message_cut_inside_reserved_octets(self) -> None:
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import FieldValueError

        swept = []
        for name, code, size in self._mh_messages():
            swept.append(name)
            mark = bytes(range(0xA1, 0xA1 + size))
            data = bytes(MH(next=59, type=code, data={'msg_reserved': mark}))
            if name in self.UNPARSED:
                # So the short read is recorded on a model parsed whole, as a
                # cut there would record it: the field ``data`` follows the
                # six octets of the MH header.
                start = data.index(mark)
                for count in range(size):
                    with self.subTest(maker=name, cut=start + count):
                        with self.assertRaises(FieldValueError):
                            MH(io.BytesIO(data[:start + count]), start + count, extension=True)
                        info = MH(io.BytesIO(data), len(data), extension=True).info
                        info.__update__({'msg_reserved': mark[:count], '__short_read__': ('data', start - 6 + count)})
                        self.assertEqual(MH.from_data(info).data, data[:start + count])
                continue
            with self.subTest(maker=name):
                self.assertCutRebuilds(MH, data, mark, extension=True)
        for name in ('_make_msg_fna', '_make_msg_has', '_make_msg_sq', *self.UNPARSED):
            self.assertIn(name, swept)

    def test_ipv6_frag_and_route_cut_inside_reserved_octets(self) -> None:
        # RFC 8200 section 4.5 and RFC 6275 section 6.4: the reserved octet
        # follows Next Header; the reserved word follows Segments Left.
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        self.assertCutRebuilds(IPv6_Frag, IPv6_Frag(next=59, reserved_octet=b'\xa1').data, b'\xa1',
                               extension=True)
        for kind, args in ((0, {'ip': ['2001:db8::1']}), (2, {'ip': '2001:db8::1'})):
            data = IPv6_Route(next=59, type=kind, data={**args, 'reserved': b'\xa1\xa2\xa3\xa4'}).data
            with self.subTest(type=kind):
                self.assertCutRebuilds(IPv6_Route, data, b'\xa1\xa2\xa3\xa4', extension=True)

    def test_ospf_cut_inside_authentication_reserved_octets(self) -> None:
        # RFC 2328 appendix D.3: cryptographic authentication opens with two
        # reserved octets, at octet 16 of the header. The dict form turns the
        # authentication data model into a mapping, which is filled the same.
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.protocols.application.ospf import OSPF

        data = OSPF(auth_type=Authentication.Cryptographic_authentication,
                    auth_data={'key_id': 1, 'len': 16, 'seq': 1, 'reserved': b'\xa1\xa2'}).data
        self.assertEqual(data.index(b'\xa1\xa2'), 16)
        start = data.index(b'\xa1\xa2')
        for cut in range(start - 1, start + 2):
            with self.subTest(cut=cut):
                info = self._parse(OSPF, data[:cut])
                self.assertIsNotNone(info.get('__short_read__'))  # type: ignore[attr-defined]
                self.assertEqual(OSPF.from_data(info).data, data[:cut])
                self.assertEqual(OSPF.from_data(info.to_dict()).data, data[:cut])  # type: ignore[attr-defined]

    def test_cut_past_the_field_keeps_it_checked(self) -> None:
        # A short read names where the capture ended; octets read whole before
        # it are checked as a caller's are, an edit to them included.
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        from pcapkit.protocols.internet.mh import MH

        def update(key: 'str') -> 'object':
            return lambda info, value: info.__update__({key: value})

        for name, code, size in self._mh_messages():
            if name in self.UNPARSED:
                continue
            mark = bytes(range(0xA1, 0xA1 + size))
            unit = 'octet' if size == 1 else 'octets'
            with self.subTest(maker=name):
                found = self.assertEditRefused(MH, bytes(MH(next=59, type=code, data={'msg_reserved': mark})),
                                               mark, update('msg_reserved'),
                                               f'MH: invalid reserved octets: must be {size} {unit}',
                                               extension=True)
                self.assertEqual(found, name not in self.NOTHING_AFTER)
        mark = b'\xa1\xa2\xa3\xa4'
        for kind, args in ((0, {'ip': ['2001:db8::1']}), (2, {'ip': '2001:db8::1'})):
            with self.subTest(type=kind):
                data = IPv6_Route(next=59, type=kind, data={**args, 'reserved': mark}).data
                self.assertTrue(self.assertEditRefused(IPv6_Route, data, mark, update('reserved'),
                                                       'IPv6-Route: invalid reserved octets: must be 4 octets',
                                                       extension=True))
        self.assertTrue(self.assertEditRefused(IPv6_Frag, IPv6_Frag(next=59, reserved_octet=b'\xa1').data, b'\xa1',
                                               update('reserved_octet'),
                                               'IPv6-Frag: invalid reserved octet: must be 1 octet', extension=True))
        data = OSPF(auth_type=Authentication.Cryptographic_authentication,
                    auth_data={'key_id': 1, 'len': 16, 'seq': 1, 'reserved': b'\xa1\xa2'}).data
        self.assertTrue(self.assertEditRefused(OSPF, data, b'\xa1\xa2',
                                               lambda info, value: info.auth.__update__({'reserved': value}),
                                               'OSPF: invalid reserved octets: must be 2 octets'))

    def test_model_of_the_wrong_width_is_refused(self) -> None:
        # A model parsed whole and edited records no short read, so its
        # octets are checked as a caller's are, through from_data or given
        # to the maker as ``message``.
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        frag = IPv6_Frag(next=59, reserved_octet=b'\xa1').data
        for value in (b'', b'\xff\xff'):
            with self.subTest(protocol='IPv6-Frag', width=len(value)):
                info = IPv6_Frag(io.BytesIO(frag), len(frag), extension=True).info
                info.__update__({'reserved_octet': value})
                with self.assertRaises(ProtocolError) as caught:
                    IPv6_Frag.from_data(info)
                self.assertEqual(str(caught.exception),
                                 f'IPv6-Frag: invalid reserved octet: must be 1 octet, not {value!r}')
        hoti = bytes(MH(next=59, type=Packet.Home_Test_Init, data={'msg_reserved': b'\xa1\xa2'}))
        for width in (0, 1, 3, 5):
            value = b'\xff' * width
            for form in ('from_data', 'message'):
                with self.subTest(protocol='MH', width=width, form=form):
                    info = MH(io.BytesIO(hoti), len(hoti), extension=True).info
                    info.__update__({'msg_reserved': value})
                    with self.assertRaises(ProtocolError) as caught:
                        if form == 'from_data':
                            MH.from_data(info)
                        else:
                            MH(next=59, type=Packet.Home_Test_Init, data={'message': info})
                    self.assertEqual(str(caught.exception),
                                     f'MH: invalid reserved octets: must be 2 octets, not {value!r}')
        for kind, args in ((0, {'ip': ['2001:db8::1']}), (2, {'ip': '2001:db8::1'})):
            route = IPv6_Route(next=59, type=kind, data={**args, 'reserved': b'\xa1\xa2\xa3\xa4'}).data
            for width in (1, 6):
                value = b'\xff' * width
                with self.subTest(protocol='IPv6-Route', type=kind, width=width):
                    info = IPv6_Route(io.BytesIO(route), len(route), extension=True).info
                    info.__update__({'reserved': value})
                    with self.assertRaises(ProtocolError) as caught:
                        IPv6_Route.from_data(info)
                    self.assertEqual(str(caught.exception),
                                     f'IPv6-Route: invalid reserved octets: must be 4 octets, not {value!r}')
        ospf = OSPF(auth_type=Authentication.Cryptographic_authentication,
                    auth_data={'key_id': 1, 'len': 16, 'seq': 1, 'reserved': b'\xa1\xa2'}).data
        for width in (0, 1, 5):
            value = b'\xff' * width
            with self.subTest(protocol='OSPF', width=width):
                info = OSPF(ospf).info
                info.auth.__update__({'reserved': value})
                with self.assertRaises(ProtocolError) as caught:
                    OSPF.from_data(info)
                self.assertEqual(str(caught.exception),
                                 f'OSPF: invalid reserved octets: must be 2 octets, not {value!r}')

if __name__ == '__main__':
    unittest.main()
