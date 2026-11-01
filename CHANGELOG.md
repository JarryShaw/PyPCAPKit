## 1.6.0 -- unreleased

Wave 2 of the roadmap, per the contributing docs' enhancement-proposal page: the protocol pairs that wanted a shared abstract base, and the two that simply had no dissector at all.

- **Added** -- `FRAD`, a dissector for Frame Relay's multiprotocol encapsulation ([RFC 2427](https://datatracker.ietf.org/doc/html/rfc2427), obsoleting [RFC 1490](https://datatracker.ietf.org/doc/html/rfc1490)). `LinuxSLL`/ `LinuxSLL1`/ `LinuxSLL2` dispatch to it for the `ARPHRD_FRAD` case instead of falling back to `Raw`; the direct NLPID and SNAP-encapsulated forms both dispatch onward, to IPv4/IPv6 and (via the EtherType registry every Ethernet/VLAN/LinuxSLL frame shares) ARP among others. The first of [#2460](https://github.com/JarryShaw/PyPCAPKit/issues/2460)'s five `arphrd_type` follow-ups to get a dissector; the other four (`NETLINK`, `IPGRE`/`IP6GRE`, `IEEE80211_RADIOTAP`) remain `Raw`.

---

Full changelog: <https://jarryshaw.github.io/PyPCAPKit/changelog.html>
