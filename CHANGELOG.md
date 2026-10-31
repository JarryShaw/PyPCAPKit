## 1.6.0 -- unreleased

Wave 2 of the roadmap, per the contributing docs' enhancement-proposal page: the protocol pairs that wanted a shared abstract base, and the two that simply had no dissector at all.

- **Added** -- `GRE`, a dissector for the Generic Routing Encapsulation base header ([RFC 2784](https://datatracker.ietf.org/doc/html/rfc2784)) plus the optional Key and Sequence Number extensions ([RFC 2890](https://datatracker.ietf.org/doc/html/rfc2890)). `LinuxSLL`/ `LinuxSLL1`/ `LinuxSLL2` dispatch to it for both the `ARPHRD_IPGRE` and `ARPHRD_IP6GRE` cases -- the same GRE framing either way, the "IP"/"IP6" distinction being only which outer IP version the tunnel carries -- instead of falling back to `Raw`. The Protocol Type field dispatches onward as an EtherType, through the same family registry (`Link.__proto__`) Ethernet, VLAN and LinuxSLL already share. One of [#2460](https://github.com/JarryShaw/PyPCAPKit/issues/2460)'s five `arphrd_type` follow-ups to get a dissector (`NETLINK` and `FRAD` are tracked separately on [#2507](https://github.com/JarryShaw/PyPCAPKit/pull/2507) and [#2499](https://github.com/JarryShaw/PyPCAPKit/pull/2499)); `IEEE80211_RADIOTAP` remains `Raw`.

---

Full changelog: <https://jarryshaw.github.io/PyPCAPKit/changelog.html>
