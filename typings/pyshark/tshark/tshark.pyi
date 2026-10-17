"""``pyshark.tshark.tshark`` as of pyshark 0.6: locating the tshark binary."""

# raises ``TSharkNotFoundException`` when no candidate path exists
def get_process_path(tshark_path: str | None = None, process_name: str = 'tshark') -> str: ...
