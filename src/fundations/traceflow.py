# -*- coding: utf-8 -*-


from jspcap.utilities.validations import pkt_check


class TraceFlow:
    """Trace TCP flows.

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def index(self):
        return self._return

    ##########################################################################
    # Methods.
    ##########################################################################

    def trace(self, info):
        """

        """
        BUFID = info.bufid  # Buffer Identifier
        SYN = info.syn      # Synchronise Flag (Establishment)
        FIN = info.fin      # Finish Flag (Termination)

        # when SYN is set, reset buffer of this seesion
        if SYN and BUFID in self._buffer:
            self._stream.append(tuple(self._buffer[BUFID]).sort(key=lambda x: x.index))
            del self._buffer[BUFID]

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            self._buffer[BUFID] = list()

        # trace frame record
        self._buffer[BUFID].append(Info(
            index = info.index,
            frame = info.frame,
        ))

        # when FIN is set, subit buffer of this session
        if FIN:
            self._stream.append(tuple(self._buffer[BUFID]).sort(key=lambda x: x.index))

    ##########################################################################
    # Data models.
    ##########################################################################

    # Not hashable
    __hash__ = None

    def __init__(self, *, fout, format):
        """

        """
        self._fdpath = fout     # output path
        self._format = format   # output format
        self._buffer = dict()   # buffer field
        self._stream = list()   # stream index

    def __call__(self, packet):
        """

        """
        pkt_check(packet)
        info = Info(packet)
        self.trace(info)
