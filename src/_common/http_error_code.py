# -*- coding: utf-8 -*-


class defaultdict(dict):
    def __missing__(self, code):
        if isinstance(code, int):
            return f'Reserved for Experimental Use [0x{hex(code)[2:].upper().zfill(8)}]'
        raise KeyError(code)


# HTTP/2 Error Code
_ERROR_CODE = defaultdict({
	0x00000000 : 'NO_ERROR',                                                       # [RFC 7540, Section 7] Graceful shutdown
	0x00000001 : 'PROTOCOL_ERROR',                                                 # [RFC 7540, Section 7] Protocol error detected
	0x00000002 : 'INTERNAL_ERROR',                                                 # [RFC 7540, Section 7] Implementation fault
	0x00000003 : 'FLOW_CONTROL_ERROR',                                             # [RFC 7540, Section 7] Flow-control limits exceeded
	0x00000004 : 'SETTINGS_TIMEOUT',                                               # [RFC 7540, Section 7] Settings not acknowledged
	0x00000005 : 'STREAM_CLOSED',                                                  # [RFC 7540, Section 7] Frame received for closed stream
	0x00000006 : 'FRAME_SIZE_ERROR',                                               # [RFC 7540, Section 7] Frame size incorrect
	0x00000007 : 'REFUSED_STREAM',                                                 # [RFC 7540, Section 7] Stream not processed
	0x00000008 : 'CANCEL',                                                         # [RFC 7540, Section 7] Stream cancelled
	0x00000009 : 'COMPRESSION_ERROR',                                              # [RFC 7540, Section 7] Compression state not updated
	0x0000000A : 'CONNECT_ERROR',                                                  # [RFC 7540, Section 7] TCP connection error for CONNECT method
	0x0000000B : 'ENHANCE_YOUR_CALM',                                              # [RFC 7540, Section 7] Processing capacity exceeded
	0x0000000C : 'INADEQUATE_SECURITY',                                            # [RFC 7540, Section 7] Negotiated TLS parameters not acceptable
	0x0000000D : 'HTTP_1_1_REQUIRED',                                              # [RFC 7540, Section 7] Use HTTP/1.1 for the request
})
