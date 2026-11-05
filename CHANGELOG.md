## 1.6.1 -- 2026-11-05

A documentation release; no library behaviour changed.

- **Changed** -- Every documentation diagram is laid out vertically, so it renders at a readable size, and new diagrams draw next-layer dispatch, the registry dispatch chain, engine selection, the `Extractor` lifecycle, reassembly triggers, TCP flow buffers, the IPv6 extension-header walk and ESP status, among others ([#2787](https://github.com/JarryShaw/PyPCAPKit/issues/2787)).

- **Changed** -- A concision and accuracy sweep of the whole repository's pages, docstrings and comments cuts restatement and narration, turns parallel prose into tables, and adds missing version directives ([#2786](https://github.com/JarryShaw/PyPCAPKit/issues/2786)).

- **Changed** -- The contributing conventions record the concision rule and the vertical, graphs-over-prose diagram convention ([#2787](https://github.com/JarryShaw/PyPCAPKit/issues/2787)).

- **Fixed** -- Documentation the code contradicted: the TCP and UDP port tables now list 443 (TLS) and 5684 (DTLS), which they bind; `Flags` refuses a value outside `0`-`0xFFF`, not the whole 16-bit field; and the `PyPCAP` extra installs on every Python below 3.12, not only 3.10 and 3.11 ([#2786](https://github.com/JarryShaw/PyPCAPKit/issues/2786)).

---

Full changelog: <https://jarryshaw.github.io/PyPCAPKit/changelog.html>
