# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.reg`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.reg.apptype.apptype:AppType': 'str',
    'pcapkit.const.reg.apptype.apptype:TransportProtocol': 'int',
    'pcapkit.const.reg.apptype.dccp:DCCP': 'str',
    'pcapkit.const.reg.apptype.sctp:SCTP': 'str',
    'pcapkit.const.reg.apptype.tcp:TCP': 'str',
    'pcapkit.const.reg.apptype.udp:UDP': 'str',
    'pcapkit.const.reg.ethertype:EtherType': 'int',
    'pcapkit.const.reg.linktype:LinkType': 'int',
    'pcapkit.const.reg.transtype:TransType': 'int',
}
