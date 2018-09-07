---
Layer: PCAP File

Acronym: Header

Reference: [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header)
---

&nbsp;

# PCAP Global Header

## Description

&emsp; This header starts the `libpcap` file and will be followed by the first packet header:

 - `magic_number`: used to detect the file format itself and the byte ordering.
 - `version_major`, `version_minor`: the version number of this file format (current version is 2.4)
 - `thiszone`: the correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps.
 - `sigfigs`: in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
 - `snaplen`: the "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user), see: incl_len vs. orig_len below
 - `network`: link-layer header type, specifying the type of headers at the beginning of the packet; this can be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc.

## Header Format

```C
typedef struct pcap_hdr_s {
    guint32 magic_number;   /\* magic number \*/
    guint16 version_major;  /\* major version number \*/
    guint16 version_minor;  /\* minor version number \*/
    gint32  thiszone;       /\* GMT to local correction \*/
    guint32 sigfigs;        /\* accuracy of timestamps \*/
    guint32 snaplen;        /\* max length of captured packets, in octets \*/
    guint32 network;        /\* data link type \*/
} pcap_hdr_t;
```

## Fields:
