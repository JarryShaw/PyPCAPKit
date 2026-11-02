# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.ftp`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.ftp.command:Command': 'str',
    'pcapkit.const.ftp.command:CommandType': 'flag',
    'pcapkit.const.ftp.command:ConformanceRequirement': 'int',
    'pcapkit.const.ftp.command:FEATCode': 'str',
    'pcapkit.const.ftp.return_code:GroupingInformation': 'int',
    'pcapkit.const.ftp.return_code:ResponseKind': 'int',
    'pcapkit.const.ftp.return_code:ReturnCode': 'int',
}
