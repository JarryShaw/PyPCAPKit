## 1.6.0 -- unreleased

Wave 2 of the roadmap, per the contributing docs' enhancement-proposal page: the protocol pairs that wanted a shared abstract base, and the two that simply had no dissector at all.

- **Added** -- `Netlink`, a dissector for the fixed 16-octet `nlmsghdr` framing of Linux's own kernel/userspace IPC transport (the kernel's own `netlink(7)` man page; [RFC 3549 Section 2.3.2](https://datatracker.ietf.org/doc/html/rfc3549#section-2.3.2)). `LinuxSLL`/ `LinuxSLL1`/ `LinuxSLL2` dispatch to it for the `ARPHRD_NETLINK` case instead of falling back to `Raw`. The byte order the header was written in is ambiguous -- Netlink is kernel/userspace IPC, not wire format -- and is guessed the way Wireshark's own netlink dissector does, by `nlmsg_byteorder()`. Per-family message payloads (routing table entries and the like) and multiple messages packed into one capture are out of scope for this first cut; every message's payload is kept as `Raw`, unconditionally. One of [#2460](https://github.com/JarryShaw/PyPCAPKit/issues/2460)'s five `arphrd_type` follow-ups to get a dissector (`FRAD` is tracked separately on [#2499](https://github.com/JarryShaw/PyPCAPKit/pull/2499)); `IPGRE`/`IP6GRE` and `IEEE80211_RADIOTAP` remain `Raw`.

---

Full changelog: <https://jarryshaw.github.io/PyPCAPKit/changelog.html>
