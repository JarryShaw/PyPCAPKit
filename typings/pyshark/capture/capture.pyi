"""``pyshark.capture.capture`` as of pyshark 0.6: the base of every capture."""

# raised for a tshark that pyshark takes to have crashed
class TSharkCrashException(Exception): ...
