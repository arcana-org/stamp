# stamp

The Simple Two-way Active Measurement Protocol (STAMP, RFC 8762) for
FreeBSD, with the Session-Sender Identifier and the Location,
Timestamp Information, Class of Service and Direct Measurement TLVs of
RFC 8972, in both modes, unauthenticated and authenticated: a library,
a Session-Reflector daemon and a sender.

- **libstamp(3)**: the packets of either mode (the authenticated one's
  112 octets and HMAC-SHA-256-128 by libcrypto, RFC 8972's HMAC TLV
  over the TLVs, a key a session's SSID, compared in constant time;
  RFC 8972's TLVs read and written, the
  Timestamp Information TLV filled by the reflector, the Class of
  Service TLV too, the DSCP each way told, the Direct Measurement TLV
  from its sessions' counters, the Location TLV from the addresses and
  ports a request came with, a NAT on the way told), NTP and PTP
  timestamps, the Error Estimate (RFC 4656) and the clock's
  synchronisation source from `ntp_gettime(2)` (or as the process says,
  for a clock the kernel does not know is synchronised), the
  Session-Reflector's core (stateless or stateful sessions, per-source
  (an IPv6 /64 one source) and global rate limits, the authenticated
  requests' apart, their sessions never replaced by unauthenticated
  ones, those failing authentication limited before any HMAC, four
  keys an SSID (a key rotated is two) and four for any, eight HMACs a
  request at most, the reply), the Session-Sender's core (a
  session's sequence, the replies matched, the round trip with the
  reflector's time taken out, the delay each way when both Error
  Estimates say synchronised and their errors together are within a
  tenth of half the round trip, else half the round trip flagged an
  estimate, the loss on the way out told from the loss on the way back
  by a stateful reflector's counter), and the UDP socket of either end (in a FIB by `SO_SETFIB`;
  kernel receive timestamps by `SO_TS_REALTIME`, or `SO_TS_MONOTONIC`
  for a sender, the TTL, the TOS and the destination address by
  `IP_RECVTTL`/`IP_RECVTOS`/`IP_RECVDSTADDR` and their IPv6 twins,
  the reply from the address the request came to, with the DSCP asked
  for). A static library needing libc and libcrypto; another
  program's sender shares it (arcana-agent's).
- **stampd(8)**: the reflector. UDP 862 (`-p`) on every address, IPv4
  and IPv6, in the FIB it is started in; root given up once bound
  (`chroot(2)` to `/var/empty`, the user `_stampd`); configuration
  read again on `SIGHUP`; its counters logged on `SIGINFO` or
  `SIGUSR1`; syslog. Keys from `stampd.keys` (`-K`), a
  file root alone reads, read before root is given up and kept open,
  read again on `SIGHUP`, whole or not at all; a request whose HMAC no
  key verifies dropped and counted, never answered; `-A` answers only
  authenticated ones.  Each descriptor limited to its rights by
  `cap_rights_limit(2)`; not in capability mode, which refuses a reply
  sent to an address.
- **stamp(1)**: send N test packets at an interval, print each reply's
  fields, the round trip and the delay each way (`-T` asks for the
  Timestamp Information TLV, `-D` for the Class of Service TLV: the
  DSCP each way, `-L` for the Location TLV: a NAT on the way, `-M` for
  the Direct Measurement TLV; `-K` sends authenticated), then the loss,
  each way from a stateful reflector, by its sequence and by the
  counters.

## FIBs, the base way

One `stampd` a FIB, each started by `rc.subr(8)`'s `stampd_fib`
(`setfib -F`):

```sh
sysrc stampd_enable=YES stampd_fibs="0 1 2"
service stampd start
```

`service stampd reload` starts the instances of FIBs newly listed, stops
those of FIBs no longer listed and sends the others `SIGHUP`, their
sessions kept. With `net.inet.udp.bind_all_fibs=1` (a loader tunable)
FIB 0's socket hears every FIB and no other binds the port: FIB 0's
alone is run, and the script says so.

Why instances rather than one daemon with a socket a FIB: the FIB is
the process's, as `setfib(1)` and `rc.subr` already give it, so the
daemon needs no FIB list of its own; and it binds once, as root, and
gives up root for good, with no privileged helper left to open the
sockets of a FIB added later.

## Build

```sh
make && make check
make install [DESTDIR=dir] [PREFIX=/usr/local]
pw useradd _stampd -d /var/empty -s /usr/sbin/nologin -c "STAMP reflector"
```

Build products go to `obj/` (or `MAKEOBJDIRPREFIX`). `make check` runs
the tests with kyua(1); those needing root are skipped without it.
FreeBSD 16.0 and later.

## License

BSD-2-Clause; see LICENSE.
