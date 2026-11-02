# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.tcp`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.tcp.checksum:Checksum': 'int',
    'pcapkit.const.tcp.flags:Flags': 'flag',
    'pcapkit.const.tcp.mp_tcp_option:MPTCPOption': 'int',
    'pcapkit.const.tcp.option:Option': 'int',
}
