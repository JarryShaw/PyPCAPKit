# -*- coding: utf-8 -*-
"""The ``hip-parameter`` family: HIP parameters.

A family module of :file:`examples/generators/options.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
# Deferring these is the design, as in options.py -- see its module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/options.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any

#: Header fields shared by every constructed HIP packet.
HIP_BASE = {
    'next': 6, 'packet': 1, 'version': 2, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: Codes tied to one HIP version, and the version their constructor demands:
#: ``R1_Counter`` (128) and ``HIP_TRANSFORM`` (577) are :rfc:`5201` only.
HIP_VERSION = {129: 2, 128: 1, 577: 1}

#: How many copies of the parameter under test go in one packet.
#:
#: One (#689), because a pair hides the length defects a single parameter
#: exposes. ``HIP.make`` computes the header's ``len`` field as
#: ``total_length // 8 + 4``, which is lossless only when the parameter octets
#: are a multiple of eight, and each parameter is padded to :rfc:`7401`
#: Section 5.2.1's ``Total Length = 11 + Length - (Length + 3) % 8`` so that it
#: is one on its own (#651). A record that is ``4 (mod 8)`` -- from padding that
#: aligns only the contents and ignores the four-octet type-and-length header
#: (#651), or from a packed length that disagrees with the declared ``Length``
#: (#672, #679) -- makes the floor division drop four octets, and
#: ``_read_hip_param``, which compares the recovered length exactly, rejects the
#: packet. Two such records sum to a multiple of eight, so a pair makes the
#: arithmetic come out exact and the defect invisible.
#:
#: ``HIP_TRANSFORM`` is HIPv1-only -- ``_read_param_hip_transform`` raises for
#: any other version -- and is built at version 1 through :data:`HIP_VERSION`.
#: ``R1_Counter`` (128) parses through ``R1CounterParameter``, which the schema
#: registry holds for both counter codes (#690). Every HIP code round-trips at
#: one copy, so :data:`tests.protocols.test_option_roundtrip_unit.EXPECTED_FAILURES`
#: has no HIP entries.
#:
#: The single-parameter case is asserted directly, and positively, by
#: ``test_a_hip_packet_carrying_one_parameter_round_trips`` in
#: :mod:`tests.protocols.test_option_roundtrip_unit`, which is also where the
#: two-copy shape is exercised, since this constant does not produce it.
HIP_COPIES = 1


def _hip_registry() -> 'Any':
    from pcapkit.const.hip.parameter import Parameter
    from pcapkit.protocols.internet.hip.protocol import HIP
    return generator._named_registry(HIP, Parameter, '_make_param_', '__parameter__')


def _hip_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.hip.ecdsa_curve import ECDSACurve
    from pcapkit.const.hip.parameter import Parameter
    return {
        # ``lifetime=0`` reaches ``math.log2(0)``.
        Parameter.PUZZLE: {'lifetime': 1},
        Parameter.SOLUTION: {'lifetime': 1},
        # ``hi_curve=None`` falls through to an explicit raise.
        Parameter.HOST_ID: {'hi_curve': ECDSACurve.NIST_P_256},
        # These two are not here because the default fails -- ``counter=0``
        # constructs and parses perfectly well. They are here because a
        # zero-valued field cannot discriminate a width defect (#672) from a
        # correct width. An RFC-only walk over ``options-internet.pcap``, which
        # takes its stride solely from :rfc:`7401` Section 5.2.1's ``Total
        # Length = 11 + Length - (Length + 3) % 8``, mis-strides over a counter
        # packed at the wrong width; where every octet it mis-reads is zero, its
        # zero-padding check passes and it reports no violation. With a non-zero
        # counter the fixture cannot conceal a mis-stride here, whether or not
        # the width is right.
        Parameter.R1_COUNTER: {'counter': 0xaabbccdd},
        Parameter.R1_Counter: {'counter': 0xaabbccdd},
    }


def _hip_base(code: 'Any') -> 'dict[str, Any]':
    base = dict(HIP_BASE)
    base['version'] = HIP_VERSION.get(int(code), 2)
    return base


def _hip_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.hip.protocol import HIP

    # ``extension=True`` is not decoration. ``HIP.alias`` reads ``self._info``,
    # which ``__post_init__`` only assigns after ``read`` returns, and the sole
    # path that returns before touching it is the ``if extension`` early exit.
    # Without it every HIP code fails with ``AttributeError: 'HIP'
    # object has no attribute '_info'``.
    return HIP(parameters=[(code, kwargs)] * HIP_COPIES,
               extension=True, **_hip_base(code))


def _hip_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.hip.protocol import HIP
    return HIP(octets, len(octets), extension=True)


def _hip_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict
    return getattr(parsed.info, 'parameters', OrderedMultiDict())


def _hip_rebuild(parameters: 'Any') -> 'Any':
    from pcapkit.protocols.internet.hip.protocol import HIP

    # ``parameters`` is the parsed collection, so the version has to come off
    # one of its members rather than from the code being tested.
    first = next(iter(parameters), None)
    base = dict(HIP_BASE)
    if first is not None:
        base['version'] = HIP_VERSION.get(int(first), 2)
    return HIP(parameters=parameters, extension=True, **base)


#: The families this module adds.
FAMILIES = (
    generator.Family('hip-parameter', _hip_registry, _hip_overrides,
                     _hip_build, _hip_parse, _hip_extract, _hip_rebuild,
                     capture='options-internet.pcap', envelope='ipv6', proto=139),
)
