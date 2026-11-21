## 1.6.2 -- 2026-11-21

A registry and bug-fix release: the vendor enumerations under `pcapkit.const` follow their upstream registries, the `1.6.1.post1` refresh included, and closing a buffered reader works on PyPy 3.12; no dissector changed.

- **Added** -- `ExtensionType` names `dane_clientid` (63), for TLS 1.3 or later, and the temporary `trust_anchors_TEMPORARY_registered_2026_11_18_expires_2027_11_18` (51764), so neither value resolves to `Unassigned`.

- **Added** -- `LinkType` names `ETW2` (305), Event Tracing for Windows messages v2; `ETW` (290) is described as v1.

- **Added** -- The app-type tables name TCP port 7151 `ambesasql` (AmbesaSQL Database Server) and UDP port 8024 `gaap` (GAAP Control Packets), and reserve each port on the other transport, so `AppType` resolves neither to `unassigned`.

- **Changed** -- Entry references follow their registries: EPP over QUIC (port 700) cites [RFC 10087](https://datatracker.ietf.org/doc/html/rfc10087), VXLAN (UDP port 4789) the draft revising [RFC 7348](https://datatracker.ietf.org/doc/html/rfc7348), and the 3GPP entries of `AccessType`, `UpdateNotificationReason` and `PayloadProtocolIdentifier` the 3GPP contact IANA lists.

- **Fixed** -- On PyPy 3.12, closing a `SeekableReader`, or tearing down an `Extractor` over a non-seekable stream, raised `BufferError`, as slices of the reader's buffer view stayed exported until collected. Each slice is released once used ([#2806](https://github.com/JarryShaw/PyPCAPKit/issues/2806)).

---

Full changelog: <https://jarryshaw.github.io/PyPCAPKit/changelog.html>
