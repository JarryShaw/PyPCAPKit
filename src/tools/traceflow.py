# coding: utf-8 -*-


class TraceFlow:
    """Trace TCP flows.

    """
    ##########################################################################
    # Methods.
    ##########################################################################

    def dump(self, packet):
        pass

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *, format):
        self._fmt = format

    def __call__(self, packet):
        self.dump(packet)
