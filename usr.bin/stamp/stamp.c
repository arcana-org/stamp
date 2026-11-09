/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * stamp: a minimal STAMP Session-Sender (RFC 8762 4.2.1, RFC 8972's
 * SSID), for tests and by hand.  count test packets to host, each
 * reply's fields on a line of its own as key=value, "none" for one
 * that did not come; a TWAMP Light sender's packet by -l (14 octets
 * and its padding).  In the FIB the process is in: setfib(1).
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "stamp.h"

static void
usage(void)
{

	fprintf(stderr, "usage: stamp [-c count] [-i interval] [-l length] "
	    "[-p port] [-q seq]\n"
	    "             [-S sport] [-s ssid] [-t ttl] [-W wait] host\n");
	exit(1);
}

static double
num(const char *opt, const char *s, double lo, double hi)
{
	char	*end;
	double	 v;

	errno = 0;
	v = strtod(s, &end);
	if (errno != 0 || *end != '\0' || end == s || v < lo || v > hi)
		errx(1, "-%s %s: from %g to %g", opt, s, lo, hi);
	return (v);
}

static const char *
ok(bool b)
{

	return (b ? "ok" : "bad");
}

int
main(int argc, char *argv[])
{
	struct sockaddr_storage	 to;
	struct stamp_test	 t;
	struct stamp_reflected	 r;
	struct stamp_rxinfo	 ri;
	struct timespec		 t1, now, ts;
	struct kevent		 kev;
	uint8_t			 pkt[STAMP_PKT_MAX], in[STAMP_PKT_MAX];
	char			 from[64];
	double			 interval = 1, wait = 2, left, rtt, sum = 0;
	double			 min = 0, max = 0;
	ssize_t			 n;
	size_t			 len = STAMP_UNAUTH_LEN, i;
	unsigned long		 count = 1, k, got = 0;
	uint32_t		 seq = 0;
	int			 ch, fd, kq, ttl = -1, port = STAMP_PORT;
	int			 sport = 0, ssid = 0;
	bool			 done;

	while ((ch = getopt(argc, argv, "c:i:l:p:q:S:s:t:W:")) != -1)
		switch (ch) {
		case 'c':
			count = (unsigned long)num("c", optarg, 1, 1000000);
			break;
		case 'i':
			interval = num("i", optarg, 0, 3600);
			break;
		case 'l':
			len = (size_t)num("l", optarg, 0, STAMP_PKT_MAX);
			break;
		case 'p':
			port = (int)num("p", optarg, 1, 65535);
			break;
		case 'q':
			seq = (uint32_t)num("q", optarg, 0, 4294967295.0);
			break;
		case 'S':
			sport = (int)num("S", optarg, 0, 65535);
			break;
		case 's':
			ssid = (int)num("s", optarg, 0, 65535);
			break;
		case 't':
			ttl = (int)num("t", optarg, 1, 255);
			break;
		case 'W':
			wait = num("W", optarg, 0.001, 3600);
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();
	if (stamp_sockaddr(argv[0], (uint16_t)port, &to) == -1)
		errx(1, "%s: no address", argv[0]);
	if ((fd = stamp_socket(to.ss_family, (uint16_t)sport, 0)) == -1)
		err(1, "a UDP socket");
	if (ttl != -1 && (to.ss_family == AF_INET ? setsockopt(fd,
	    IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) : setsockopt(fd,
	    IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl))) == -1)
		err(1, "the TTL");
	if ((kq = kqueue()) == -1)
		err(1, "kqueue");
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		err(1, "kevent");
	/* What follows the base: a pattern, to see it come back. */
	for (i = STAMP_UNAUTH_LEN; i < sizeof(pkt); i++)
		pkt[i] = (uint8_t)i;

	for (k = 0; k < count; k++) {
		memset(&t, 0, sizeof(t));
		t.seq = seq + (uint32_t)k;
		t.ee = stamp_ee_clock();
		t.ssid = (uint16_t)ssid;
		clock_gettime(CLOCK_REALTIME, &t1);
		t.ts = t1;
		(void)stamp_test_encode(pkt, sizeof(pkt), &t);
		if (sendto(fd, pkt, len, 0, (struct sockaddr *)&to, to.ss_len) ==
		    -1)
			err(1, "sendto");
		/* Its reply, up to wait; another's (late) passed over. */
		done = false;
		while (!done) {
			clock_gettime(CLOCK_REALTIME, &now);
			if ((left = wait - stamp_ts_sub(&now, &t1)) <= 0)
				break;
			ts.tv_sec = (time_t)left;
			ts.tv_nsec = (long)((left - (double)ts.tv_sec) * 1e9);
			if (kevent(kq, NULL, 0, &kev, 1, &ts) <= 0)
				break;
			while ((n = stamp_recv(fd, in, sizeof(in), &ri)) != -1) {
				if (n < STAMP_UNAUTH_LEN) {
					printf("len=%zd short\n", n);
					continue;
				}
				(void)stamp_reflected_decode(in, (size_t)n, &r);
				if (r.sseq != t.seq || len < STAMP_UNAUTH_LEN)
					continue;
				clock_gettime(CLOCK_REALTIME, &now);
				rtt = stamp_ts_sub(&ri.t, &t1) -
				    stamp_ts_sub(&r.ts, &r.rx);
				printf("len=%zd from=%s seq=%u ssid=%u sseq=%u "
				    "ttl=%u rttl=%d echo=%s order=%s clock=%s "
				    "serr=%s mbz=%s pad=%s rtt=%.3f fwd=%.3f "
				    "back=%.3f\n", n, stamp_sa_ntop((struct
				    sockaddr *)&ri.peer, from, sizeof(from)),
				    r.seq, r.ssid, r.sseq, r.sttl, ri.ttl,
				    ok(memcmp(in + 28, pkt + 4, 10) == 0),
				    ok(stamp_ts_sub(&r.rx, &r.ts) <= 0),
				    ok(fabs(stamp_ts_sub(&r.rx, &now)) < 5 &&
				    fabs(stamp_ts_sub(&r.ts, &now)) < 5),
				    ok((r.ee & 0xff) != 0), ok(r.mbz_ok),
				    ok((size_t)n == len && memcmp(in +
				    STAMP_UNAUTH_LEN, pkt + STAMP_UNAUTH_LEN,
				    (size_t)n - STAMP_UNAUTH_LEN) == 0),
				    rtt * 1e3, stamp_ts_sub(&r.rx, &t1) * 1e3,
				    stamp_ts_sub(&ri.t, &r.ts) * 1e3);
				if (got == 0 || rtt < min)
					min = rtt;
				if (got == 0 || rtt > max)
					max = rtt;
				sum += rtt;
				got++;
				done = true;
				break;
			}
		}
		if (!done)
			printf("none\n");
		(void)fflush(stdout);
		if (k + 1 < count && interval > 0) {
			clock_gettime(CLOCK_REALTIME, &now);
			if ((left = interval - stamp_ts_sub(&now, &t1)) > 0)
				(void)usleep((useconds_t)(left * 1e6));
		}
	}
	if (count > 1) {
		printf("sent=%lu received=%lu", count, got);
		if (got > 0)
			printf(" rtt=%.3f/%.3f/%.3f", min * 1e3, sum / (double)got *
			    1e3, max * 1e3);
		printf("\n");
	}
	return (got > 0 ? 0 : 2);
}
