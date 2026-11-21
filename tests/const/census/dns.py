# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.dns`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.dns.opcode:Opcode': 'int',
    'pcapkit.const.dns.option:Option': 'int',
    'pcapkit.const.dns.rcode:RCode': 'int',
    'pcapkit.const.dns.rr_class:RRClass': 'int',
    'pcapkit.const.dns.rr_type:RRType': 'int',
}
