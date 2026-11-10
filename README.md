# stamp

The Simple Two-way Active Measurement Protocol (STAMP, RFC 8762) for
FreeBSD, with the Session-Sender Identifier and the Timestamp
Information TLV of RFC 8972: a library, a Session-Reflector daemon and
a sender.

- **libstamp(3)**: the packets of the unauthenticated mode (room left
  for the authenticated one; RFC 8972's TLVs read and written, the
  Timestamp Information TLV filled by the reflector), NTP and PTP
  timestamps, the Error Estimate (RFC 4656) and the clock's
  synchronisation source from `ntp_gettime(2)` (or as the process says,
  for a clock the kernel does not know is synchronised), the
  Session-Reflector's core (stateless or stateful sessions, per-source
  and global rate limits, the reply), the Session-Sender's core (a
  session's sequence, the replies matched, the round trip with the
  reflector's time taken out, the delay each way when both Error
  Estimates say synchronised and their errors together are within a
  tenth of half the round trip, else half the round trip flagged an
  estimate, the loss on the way out told from the loss on the way back
  by a stateful reflector's counter), and the UDP socket of either end (in a FIB by `SO_SETFIB`;
  kernel receive timestamps by `SO_TS_REALTIME`, or `SO_TS_MONOTONIC`
  for a sender, the TTL and destination address by
  `IP_RECVTTL`/`IP_RECVDSTADDR`/`IPV6_RECVPKTINFO`, the reply from the
  address the request came to). A static library with no dependency
  but libc; another program's sender shares it (arcana-agent's).
- **stampd(8)**: the reflector. UDP 862 (`-p`) on every address, IPv4
  and IPv6, in the FIB it is started in; root given up once bound
  (`chroot(2)` to `/var/empty`, the user `_stampd`); configuration
  read again on `SIGHUP`; syslog.
- **stamp(1)**: send N test packets at an interval, print each reply's
  fields, the round trip and the delay each way (`-T` asks for the
  Timestamp Information TLV), then the loss, each way from a stateful
  reflector.

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
