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
 * Information TLV; -D sends the packets with a DSCP and asks, by the
 * Class of Service TLV, for the replies to come back with it; -M asks
 * for the Direct Measurement TLV (the loss each way by counters), -L
 * for the Location TLV (a NAT on the way seen); -C says this clock's
 * synchronisation; -K sends in the authenticated mode, under a key of
 * the file's (its SSID's when -s says one, else the first, its SSID
 * then the key's).  A TWAMP
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
#include <fcntl.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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

	fprintf(stderr, "usage: stamp [-LMT] [-C source[:error]] [-c count] "
	    "[-D dscp[/reply]]\n"
	    "             [-i interval] [-K keyfile] [-l length] [-m mode] "
	    "[-p port]\n"
	    "             [-q seq] [-S sport] [-s ssid] [-t ttl] [-W wait] "
	    "host\n");
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

/* The Class of Service TLV as the reflector filled it, and the DSCP
 * the reply came with: "cos=DSCP1/DSCP2/ECN/RP rdscp=D", "-" for what
 * was not said. */
static const char *
cos_say(const struct stamp_sample *sm, const struct stamp_rxinfo *ri)
{
	static char	buf[64];

	if (sm->has_cos)
		(void)snprintf(buf, sizeof(buf), " cos=%u/%u/%u/%u",
		    sm->cos.dscp1, sm->cos.dscp2, sm->cos.ecn, sm->cos.rp);
	else
		(void)snprintf(buf, sizeof(buf), " cos=-");
	if (ri->tos >= 0)
		(void)snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		    " rdscp=%d", ri->tos >> 2);
	else
		(void)strlcat(buf, " rdscp=-", sizeof(buf));
	return (buf);
}

/* The Direct Measurement TLV's counters, " dm=S_TxC/R_RxC/R_TxC/S_RxC",
 * "dm=-" when the reflector did not count. */
static const char *
dm_say(const struct stamp_sample *sm)
{
	static char	buf[64];

	if (!sm->has_dm)
		return (" dm=-");
	(void)snprintf(buf, sizeof(buf), " dm=%u/%u/%u/%u", sm->dm.s_tx,
	    sm->dm.r_rx, sm->dm.r_tx, sm->s_rx);
	return (buf);
}

/* An address and port as "a:p", "[a]:p" for IPv6, "-" not said. */
static const char *
ap(const struct sockaddr_storage *ss, char *buf, size_t len)
{
	char	a[64];

	if (ss->ss_family == 0)
		(void)snprintf(buf, len, "-");
	else
		(void)snprintf(buf, len, ss->ss_family == AF_INET6 ? "[%s]:%u" :
		    "%s:%u", stamp_sa_ntop((const struct sockaddr *)ss, a,
		    sizeof(a)), stamp_sa_port((const struct sockaddr *)ss));
	return (buf);
}

/* The Location TLV: " src=a:p dst=a:p nat=src,dst|none", the source
 * and destination as the reflector saw them, and what of them is not
 * this end's address and port (self) and the one it sent to (far). */
static const char *
loc_say(const struct stamp_sample *sm, const struct sockaddr *self,
    const struct sockaddr *far)
{
	static char	buf[160];
	char		s1[64], s2[64];
	int		nat;

	if (!sm->has_loc)
		return (" src=- dst=- nat=-");
	nat = stamp_location_nat(&sm->loc, self, far);
	(void)snprintf(buf, sizeof(buf), " src=%s dst=%s nat=%s",
	    ap(&sm->loc.src, s1, sizeof(s1)), ap(&sm->loc.dst, s2, sizeof(s2)),
	    nat == 0 ? "none" : nat == STAMP_NAT_SRC ? "src" : nat ==
	    STAMP_NAT_DST ? "dst" : "src,dst");
	return (buf);
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
	struct sockaddr_storage	  to, self;
	socklen_t		  slen;
	struct timespec		  t1, ts;
	struct kevent		  kev;
	uint8_t			  pkt[STAMP_PKT_MAX], in[STAMP_PKT_MAX];
	char			  from[64], *slash;
	double			  interval = 1, wait = 2, start, at, until, now;
	double			  sum = 0, min = 0, max = 0, left, ex;
	double			  fsum = 0, bsum = 0;
	ssize_t			  n;
	size_t			  len = STAMP_UNAUTH_LEN, plen, pad, i;
	unsigned long		  count = 1, k = 0, measured = 0;
	int			  ch, fd, kq, ttl = -1, port = STAMP_PORT;
	int			  sport = 0, rc, dscp = -1, v, kfd;
	struct stamp_key	 *keys = NULL, key;
	size_t			  nkeys = 0, base;
	const char		 *keyfile = NULL;
	char			  why[256];
	bool			  ssid_set = false, lset = false;

	memset(&sc, 0, sizeof(sc));
	while ((ch = getopt(argc, argv, "C:c:D:i:K:Ll:Mm:p:q:S:s:Tt:W:")) != -1)
		switch (ch) {
		case 'K':
			keyfile = optarg;
			break;
		case 'C':
			if (stamp_clock_set(optarg) == -1)
				errx(1, "-C %s: ntp, ptp, ssu, gnss or local, "
				    "and :error in seconds", optarg);
			break;
		case 'T':
			sc.tsinfo = true;
			break;
		case 'L':
			sc.location = true;
			break;
		case 'M':
			sc.dm = true;
			break;
		case 'c':
			count = (unsigned long)num("c", optarg, 1, 1000000);
			break;
		case 'D':
			/* dscp[/reply]: the packets', the replies' asked. */
			if ((slash = strchr(optarg, '/')) != NULL)
				*slash++ = '\0';
			dscp = (int)num("D", optarg, 0, 63);
			sc.cos = true;
			sc.dscp = (uint8_t)(slash != NULL ? num("D", slash, 0,
			    63) : dscp);
			break;
		case 'i':
			interval = num("i", optarg, 0, 3600);
			break;
		case 'l':
			len = (size_t)num("l", optarg, 0, STAMP_PKT_MAX);
			lset = true;
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
			ssid_set = true;
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
	/* The key: the SSID's, or the first and its SSID. */
	if (keyfile != NULL) {
		if ((kfd = open(keyfile, O_RDONLY | O_CLOEXEC)) == -1)
			err(1, "%s", keyfile);
		if (stamp_keys_read(kfd, &keys, &nkeys, why, sizeof(why)) == -1)
			errx(1, "%s: %s", keyfile, why);
		close(kfd);
		for (i = 0; i < nkeys; i++)
			if (!ssid_set || keys[i].ssid == STAMP_SSID_ANY ||
			    keys[i].ssid == sc.ssid)
				break;
		if (i == nkeys)
			errx(1, "%s: no key for SSID %u", keyfile, sc.ssid);
		key = keys[i];
		stamp_keys_free(keys, nkeys);
		if (!ssid_set && key.ssid != STAMP_SSID_ANY)
			sc.ssid = (uint16_t)key.ssid;
		sc.key = &key;
	}
	base = sc.key != NULL ? STAMP_AUTH_LEN : STAMP_UNAUTH_LEN;
	if (!lset)
		len = base;
	if (stamp_sockaddr(argv[0], (uint16_t)port, &to) == -1)
		errx(1, "%s: no address", argv[0]);
	if ((fd = stamp_socket(to.ss_family, (uint16_t)sport,
	    STAMP_SOCK_MONOTONIC)) == -1)
		err(1, "a UDP socket");
	if (ttl != -1 && (to.ss_family == AF_INET ? setsockopt(fd,
	    IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) : setsockopt(fd,
	    IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl))) == -1)
		err(1, "the TTL");
	v = dscp << 2;
	if (dscp != -1 && (to.ss_family == AF_INET ? setsockopt(fd,
	    IPPROTO_IP, IP_TOS, &v, sizeof(v)) : setsockopt(fd,
	    IPPROTO_IPV6, IPV6_TCLASS, &v, sizeof(v))) == -1)
		err(1, "the DSCP");
	if ((kq = kqueue()) == -1)
		err(1, "kqueue");
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		err(1, "kevent");
	sc.timeout = wait;
	sc.window = WINDOW;
	if ((snd = stamp_sender_new(&sc)) == NULL)
		err(1, "the sender");
	if (sc.key != NULL)
		explicit_bzero(&key, sizeof(key));
	if (sc.key != NULL && len < base)
		errx(1, "-l %zu: the authenticated mode's packets are %zu octets "
		    "or more", len, base);
	/*
	 * What follows the base: a pattern, to see it come back; with -T
	 * or -D the TLVs first, the pattern in an Extra Padding TLV after
	 * them, the packet as long as they need.  Without, the base
	 * whatever the length (a short one to see it refused).
	 */
	for (i = STAMP_UNAUTH_LEN; i < sizeof(pkt); i++)
		pkt[i] = (uint8_t)i;
	pad = base;
	if (sc.tsinfo || sc.cos || sc.dm || sc.location || sc.key != NULL) {
		len = stamp_sender_len(snd, len);
		plen = len;
		pad = stamp_sender_len(snd, 0);
	} else
		plen = sizeof(pkt);

	stamp_sender_stats(snd, &st);
	start = stamp_mono();
	for (;;) {
		now = stamp_mono();
		/* The next packet, when its time has come. */
		if (k < count && now >= start + (double)k * interval) {
			/* Authenticated, made in place: the pattern again. */
			if (sc.key != NULL)
				for (i = STAMP_UNAUTH_LEN; i < sizeof(pkt); i++)
					pkt[i] = (uint8_t)i;
			clock_gettime(CLOCK_REALTIME, &t1);
			if ((rc = stamp_sender_packet(snd, pkt, plen, &t1,
			    now, &sm)) == -1)
				err(1, "a packet");
			if (rc == 1)
				printf("none\n");
			memcpy(sent10[seq_of(pkt) & (WINDOW - 1)], pkt + (sc.key !=
			    NULL ? 16 : 4), 10);
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
			/* This end as it sent: the address the reply came to,
			 * the socket's port. */
			memset(&self, 0, sizeof(self));
			slen = sizeof(self);
			if (ri.local.ss_family != 0 && getsockname(fd,
			    (struct sockaddr *)&self, &slen) == 0) {
				uint16_t	sp = stamp_sa_port((struct sockaddr *)
				    &self);

				self = ri.local;
				if (self.ss_family == AF_INET)
					((struct sockaddr_in *)(void *)&self)->
					    sin_port = htons(sp);
				else
					((struct sockaddr_in6 *)(void *)&self)->
					    sin6_port = htons(sp);
			} else
				memset(&self, 0, sizeof(self));
			/* Another's, late, again: passed over. */
			if (stamp_sender_reply(snd, in, (size_t)n, at, &ri.t,
			    &sm) != 1)
				continue;
			printf("len=%zd from=%s seq=%u ssid=%u sseq=%u ttl=%u "
			    "rttl=%d echo=%s order=%s clock=%s serr=%s mbz=%s "
			    "pad=%s rtt=%.3f fwd=%.3f back=%.3f owd=%s err=%.6f "
			    "ti=%s%s%s%s\n", n,
			    stamp_sa_ntop((struct sockaddr *)&ri.peer, from,
			    sizeof(from)), sm.r.seq, sm.r.ssid, sm.r.sseq,
			    sm.r.sttl, ri.ttl, ok(memcmp(in + (sc.key != NULL ? 64 :
			    28), sent10[sm.seq & (WINDOW - 1)], 10) == 0),
			    ok(stamp_ts_sub(&sm.r.rx, &sm.r.ts) <= 0),
			    ok(fabs(stamp_ts_sub(&sm.r.rx, &ri.t)) < 5 &&
			    fabs(stamp_ts_sub(&sm.r.ts, &ri.t)) < 5),
			    ok((sm.r.ee & 0xff) != 0), ok(sm.r.mbz_ok),
			    ok((size_t)n == len && memcmp(in + pad, pkt + pad,
			    (size_t)n - pad) == 0), sm.rtt * 1e3, sm.fwd * 1e3,
			    sm.back * 1e3, sm.owd ? "measured" : "estimated",
			    sm.err * 1e3, tsinfo(&sm), sc.cos ? cos_say(&sm, &ri) :
			    "", sc.dm ? dm_say(&sm) : "", sc.location ?
			    loc_say(&sm, self.ss_family != 0 ? (struct sockaddr *)
			    &self : NULL, (struct sockaddr *)&to) : "");
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
		if (sc.dm && st.dm_told)
			printf(" dm_forward=%ju dm_backward=%ju",
			    (uintmax_t)st.dm_fwd_lost, (uintmax_t)st.dm_back_lost);
		else if (sc.dm)
			printf(" dm_forward=- dm_backward=-");
		printf("\n");
	}
	/* Replies passed over: tampered with, or not of the key. */
	if (sc.key != NULL && (st.auth_failed > 0 || st.tlv_failed > 0))
		printf("auth_failed=%ju tlv_failed=%ju\n",
		    (uintmax_t)st.auth_failed, (uintmax_t)st.tlv_failed);
	stamp_sender_free(snd);
	return (st.received > 0 ? 0 : 2);
}
