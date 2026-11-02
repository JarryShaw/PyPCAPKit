# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.icmp`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.icmp.destination_unreachable_code:DestinationUnreachableCode': 'int',
    'pcapkit.const.icmp.parameter_problem_code:ParameterProblemCode': 'int',
    'pcapkit.const.icmp.time_exceeded_code:TimeExceededCode': 'int',
    'pcapkit.const.icmp.type:Type': 'int',
}
