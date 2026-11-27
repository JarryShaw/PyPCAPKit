# -*- coding: utf-8 -*-
"""The registries of :mod:`pcapkit.const.icmpv6`, for :mod:`tests.const.census`."""

#: Each registry, as ``module:QualName``, and its kind.
REGISTRIES = {
    'pcapkit.const.icmpv6.destination_unreachable_code:DestinationUnreachableCode': 'int',
    'pcapkit.const.icmpv6.nd_option:NDOption': 'int',
    'pcapkit.const.icmpv6.parameter_problem_code:ParameterProblemCode': 'int',
    'pcapkit.const.icmpv6.router_preference:RouterPreference': 'int',
    'pcapkit.const.icmpv6.time_exceeded_code:TimeExceededCode': 'int',
    'pcapkit.const.icmpv6.type:Type': 'int',
}
