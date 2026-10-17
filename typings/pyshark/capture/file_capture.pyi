"""``pyshark.capture.file_capture`` as of pyshark 0.6: the capture read from a file."""
import asyncio
import os
from typing import Any

from pyshark.packet.packet import Packet

# pyshark derives this from ``pyshark.capture.capture.Capture``, which is where
# ``close`` is defined
class FileCapture:
    def __init__(self, input_file: str | os.PathLike[str] | None = None, keep_packets: bool = True,
                 display_filter: str | None = None, only_summaries: bool = False,
                 decryption_key: str | None = None, encryption_type: str = 'wpa-pwk',
                 decode_as: dict[str, str] | None = None, disable_protocol: str | None = None,
                 tshark_path: str | None = None, override_prefs: dict[str, str] | None = None,
                 use_json: bool = False, use_ek: bool = False, output_file: str | None = None,
                 include_raw: bool = False, eventloop: asyncio.AbstractEventLoop | None = None,
                 custom_parameters: dict[str, Any] | list[str] | None = None,
                 debug: bool = False) -> None: ...
    def next(self) -> Packet: ...
    def close(self) -> None: ...
