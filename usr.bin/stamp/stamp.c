/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * stamp: a STAMP Session-Sender (RFC 8762 4.2.1, RFC 8972's SSID) on
 * libstamp's sender core, for tests and by hand.  count test packets
 * to host, one every interval whatever came back, each reply's fields
 * on a line of its own as key=value, "none" for one that did not come
 * within the wait; at the end the loss, each way when the reflector is
 * stateful, and the delay each way, one way when both clocks allow,
 * else half the round trip.  -T asks for the reflector's Timestamp
 * Information TLV; -C says this clock's synchronisation.  A TWAMP
 * Light sender's packet by -l (14 octets and its padding).  In the FIB
 * the process is in: setfib(1).
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

/* What each packet in flight carried, to see it echoed: its timestamp
 * and error estimate, by its sequence number. */
#define	WINDOW	4096
static uint8_t	sent10[WINDOW][10];

static void
usage(void)
{

	fprintf(stderr, "usage: stamp [-T] [-C source[:error]] [-c count] "
	    "[-i interval] [-l length]\n"
	    "             [-m mode] [-p port] [-q seq] [-S sport] [-s ssid] "
	    "[-t ttl]\n"
	    "             [-W wait] host\n");
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

/* The reflector's Timestamp Information, "-" with none. */
static const char *
tsinfo(const struct stamp_sample *sm)
{
	static char	buf[64];

	if (!sm->has_tsinfo)
		return ("-");
	(void)snprintf(buf, sizeof(buf), "%s/", stamp_sync_name(
	    sm->tsinfo.sync_in));
	(void)strlcat(buf, stamp_tsm_name(sm->tsinfo.ts_in), sizeof(buf));
	(void)strlcat(buf, ",", sizeof(buf));
	(void)strlcat(buf, stamp_sync_name(sm->tsinfo.sync_out), sizeof(buf));
	(void)strlcat(buf, "/", sizeof(buf));
	(void)strlcat(buf, stamp_tsm_name(sm->tsinfo.ts_out), sizeof(buf));
	return (buf);
}

static uint32_t
seq_of(const uint8_t *p)
{

	return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | p[3]);
}

int
main(int argc, char *argv[])
{
	struct stamp_sender_conf  sc;
	struct stamp_sender	 *snd;
	struct stamp_sender_stats st;
	struct stamp_sample	  sm;
	struct stamp_rxinfo	  ri;
	struct sockaddr_storage	  to;
	struct timespec		  t1, ts;
	struct kevent		  kev;
	uint8_t			  pkt[STAMP_PKT_MAX], in[STAMP_PKT_MAX];
	char			  from[64];
	double			  interval = 1, wait = 2, start, at, until, now;
	double			  sum = 0, min = 0, max = 0, left, ex;
	double			  fsum = 0, bsum = 0;
	ssize_t			  n;
	size_t			  len = STAMP_UNAUTH_LEN, plen, pad, i;
	unsigned long		  count = 1, k = 0, measured = 0;
	int			  ch, fd, kq, ttl = -1, port = STAMP_PORT;
	int			  sport = 0, rc;

	memset(&sc, 0, sizeof(sc));
	while ((ch = getopt(argc, argv, "C:c:i:l:m:p:q:S:s:Tt:W:")) != -1)
		switch (ch) {
		case 'C':
			if (stamp_clock_set(optarg) == -1)
				errx(1, "-C %s: ntp, ptp, ssu, gnss or local, "
				    "and :error in seconds", optarg);
			break;
		case 'T':
			sc.tsinfo = true;
			break;
		case 'c':
			count = (unsigned long)num("c", optarg, 1, 1000000);
			break;
		case 'i':
			interval = num("i", optarg, 0, 3600);
			break;
		case 'l':
			len = (size_t)num("l", optarg, 0, STAMP_PKT_MAX);
			break;
		case 'm':
			if (strcmp(optarg, "stateless") == 0)
				sc.mode = STAMP_MODE_STATELESS;
			else if (strcmp(optarg, "stateful") == 0)
				sc.mode = STAMP_MODE_STATEFUL;
			else
				errx(1, "-m %s: stateless or stateful", optarg);
			break;
		case 'p':
			port = (int)num("p", optarg, 1, 65535);
			break;
		case 'q':
			sc.seq0 = (uint32_t)num("q", optarg, 0, 4294967295.0);
			sc.seq_set = true;
			break;
		case 'S':
			sport = (int)num("S", optarg, 0, 65535);
			break;
		case 's':
			sc.ssid = (uint16_t)num("s", optarg, 0, 65535);
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
	if ((fd = stamp_socket(to.ss_family, (uint16_t)sport,
	    STAMP_SOCK_MONOTONIC)) == -1)
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
	sc.timeout = wait;
	sc.window = WINDOW;
	if ((snd = stamp_sender_new(&sc)) == NULL)
		err(1, "the sender");
	/*
	 * What follows the base: a pattern, to see it come back; with -T
	 * the TLV first, the pattern in an Extra Padding TLV after it,
	 * the packet as long as they need.  Without, the base whatever
	 * the length (a short one to see it refused).
	 */
	for (i = STAMP_UNAUTH_LEN; i < sizeof(pkt); i++)
		pkt[i] = (uint8_t)i;
	pad = STAMP_UNAUTH_LEN;
	if (sc.tsinfo) {
		len = stamp_sender_len(snd, len);
		plen = len;
		pad += STAMP_TSINFO_LEN;
	} else
		plen = sizeof(pkt);

	stamp_sender_stats(snd, &st);
	start = stamp_mono();
	for (;;) {
		now = stamp_mono();
		/* The next packet, when its time has come. */
		if (k < count && now >= start + (double)k * interval) {
			clock_gettime(CLOCK_REALTIME, &t1);
			if ((rc = stamp_sender_packet(snd, pkt, plen, &t1,
			    now, &sm)) == -1)
				err(1, "a packet");
			if (rc == 1)
				printf("none\n");
			memcpy(sent10[seq_of(pkt) & (WINDOW - 1)], pkt + 4, 10);
			if (sendto(fd, pkt, len, 0, (struct sockaddr *)&to,
			    to.ss_len) == -1)
				err(1, "sendto");
			k++;
			continue;
		}
		while (stamp_sender_expire(snd, now, &sm) == 1)
			printf("none\n");
		stamp_sender_stats(snd, &st);
		if (k == count && st.received + st.lost == st.sent)
			break;
		/* Until the next packet, or the oldest one's wait. */
		until = k < count ? start + (double)k * interval : 0;
		if ((ex = stamp_sender_next(snd)) > 0 && (until == 0 ||
		    ex < until))
			until = ex;
		if ((left = until - now) < 0)
			left = 0;
		ts.tv_sec = (time_t)left;
		ts.tv_nsec = (long)((left - (double)ts.tv_sec) * 1e9);
		(void)fflush(stdout);
		if (kevent(kq, NULL, 0, &kev, 1, &ts) <= 0)
			continue;
		while ((n = stamp_recv(fd, in, sizeof(in), &ri)) != -1) {
			if (n < STAMP_UNAUTH_LEN) {
				printf("len=%zd short\n", n);
				continue;
			}
			at = (double)ri.mono.tv_sec + (double)ri.mono.tv_nsec /
			    1e9;
			/* Another's, late, again: passed over. */
			if (stamp_sender_reply(snd, in, (size_t)n, at, &ri.t,
			    &sm) != 1)
				continue;
			printf("len=%zd from=%s seq=%u ssid=%u sseq=%u ttl=%u "
			    "rttl=%d echo=%s order=%s clock=%s serr=%s mbz=%s "
			    "pad=%s rtt=%.3f fwd=%.3f back=%.3f owd=%s err=%.6f "
			    "ti=%s\n", n,
			    stamp_sa_ntop((struct sockaddr *)&ri.peer, from,
			    sizeof(from)), sm.r.seq, sm.r.ssid, sm.r.sseq,
			    sm.r.sttl, ri.ttl, ok(memcmp(in + 28,
			    sent10[sm.seq & (WINDOW - 1)], 10) == 0),
			    ok(stamp_ts_sub(&sm.r.rx, &sm.r.ts) <= 0),
			    ok(fabs(stamp_ts_sub(&sm.r.rx, &ri.t)) < 5 &&
			    fabs(stamp_ts_sub(&sm.r.ts, &ri.t)) < 5),
			    ok((sm.r.ee & 0xff) != 0), ok(sm.r.mbz_ok),
			    ok((size_t)n == len && memcmp(in + pad, pkt + pad,
			    (size_t)n - pad) == 0), sm.rtt * 1e3, sm.fwd * 1e3,
			    sm.back * 1e3, sm.owd ? "measured" : "estimated",
			    sm.err * 1e3, tsinfo(&sm));
			fsum += sm.fwd;
			bsum += sm.back;
			if (sm.owd)
				measured++;
			if (st.received == 0 || sm.rtt < min)
				min = sm.rtt;
			if (st.received == 0 || sm.rtt > max)
				max = sm.rtt;
			sum += sm.rtt;
			stamp_sender_stats(snd, &st);
		}
	}
	if (count > 1) {
		printf("sent=%ju received=%ju lost=%ju", (uintmax_t)st.sent,
		    (uintmax_t)st.received, (uintmax_t)st.lost);
		/* Those lost after the last reply are not told apart. */
		if (st.mode == STAMP_MODE_STATEFUL)
			printf(" forward=%ju backward=%ju unknown=%ju",
			    (uintmax_t)st.fwd_lost, (uintmax_t)st.back_lost,
			    (uintmax_t)(st.lost - st.fwd_lost - st.back_lost));
		else
			printf(" forward=- backward=-");
		printf(" reflector=%s", stamp_mode_name(st.mode));
		if (st.received > 0)
			printf(" rtt=%.3f/%.3f/%.3f fwd=%.3f back=%.3f "
			    "measured=%lu", min * 1e3, sum / (double)st.received *
			    1e3, max * 1e3, fsum / (double)st.received * 1e3,
			    bsum / (double)st.received * 1e3, measured);
		printf("\n");
	}
	stamp_sender_free(snd);
	return (st.received > 0 ? 0 : 2);
}
