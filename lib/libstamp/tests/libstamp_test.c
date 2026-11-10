/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "stamp.h"

static struct sockaddr_in
sin4(const char *a, uint16_t port)
{
	struct sockaddr_in	s;

	memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_len = sizeof(s);
	s.sin_port = htons(port);
	ATF_REQUIRE(inet_pton(AF_INET, a, &s.sin_addr) == 1);
	return (s);
}

static struct sockaddr_in6
sin6(const char *a, uint16_t port)
{
	struct sockaddr_in6	s;

	memset(&s, 0, sizeof(s));
	s.sin6_family = AF_INET6;
	s.sin6_len = sizeof(s);
	s.sin6_port = htons(port);
	ATF_REQUIRE(inet_pton(AF_INET6, a, &s.sin6_addr) == 1);
	return (s);
}

/* A sender's packet of len octets (padded with a pattern). */
static void
pkt_make(uint8_t *p, size_t len, uint32_t seq, uint16_t ssid)
{
	struct stamp_test	t;
	size_t			i;

	memset(&t, 0, sizeof(t));
	t.seq = seq;
	t.ee = stamp_ee_make(true, false, 0.001);
	t.ssid = ssid;
	clock_gettime(CLOCK_REALTIME, &t.ts);
	for (i = 0; i < len; i++)
		p[i] = (uint8_t)(i * 7);
	ATF_REQUIRE(stamp_test_encode(p, len < STAMP_UNAUTH_LEN ?
	    STAMP_UNAUTH_LEN : len, &t) == 0);
}

/* A reflector's reply to a packet; its length, or -1 and why. */
static ssize_t
reply(struct stamp_refl *r, const uint8_t *p, size_t len,
    const struct sockaddr *peer, const struct sockaddr *local, int tag,
    double mono, uint8_t *out, enum stamp_drop *why)
{
	struct stamp_rx	rx;

	memset(&rx, 0, sizeof(rx));
	rx.pkt = p;
	rx.len = len;
	rx.peer = peer;
	rx.local = local;
	rx.ttl = 77;
	clock_gettime(CLOCK_REALTIME, &rx.t2);
	rx.tag = tag;
	rx.mono = mono;
	return (stamp_refl_reply(r, &rx, out, STAMP_PKT_MAX, why));
}

static uint32_t
seq_of(const uint8_t *out)
{
	struct stamp_reflected	rf;

	ATF_REQUIRE(stamp_reflected_decode(out, STAMP_UNAUTH_LEN, &rf) == 0);
	return (rf.seq);
}

ATF_TC_WITHOUT_HEAD(ntp_roundtrip);
ATF_TC_BODY(ntp_roundtrip, tc)
{
	struct timespec	in[] = {
		{ 0, 0 }, { 1700000000, 999999999 }, { 1778400000, 123456789 },
		{ 2209000000LL, 500000000 },	/* 2040: NTP's era 1 */
	}, out;
	uint8_t		b[8];
	size_t		i;

	for (i = 0; i < nitems(in); i++) {
		stamp_ntp_put(b, &in[i]);
		stamp_ntp_get(b, &out);
		ATF_CHECK_EQ_MSG(out.tv_sec, in[i].tv_sec, "%zu", i);
		ATF_CHECK_MSG(out.tv_nsec - in[i].tv_nsec <= 1 &&
		    in[i].tv_nsec - out.tv_nsec <= 1, "%zu: %ld %ld", i,
		    out.tv_nsec, in[i].tv_nsec);
		stamp_ptp_put(b, &in[i]);
		stamp_ptp_get(b, &out);
		ATF_CHECK_EQ((uint32_t)out.tv_sec, (uint32_t)in[i].tv_sec);
		ATF_CHECK_EQ(out.tv_nsec, in[i].tv_nsec);
	}
	/* 1970 in NTP: 2208988800 seconds. */
	stamp_ntp_put(b, &in[0]);
	ATF_CHECK(b[0] == 0x83 && b[1] == 0xaa && b[2] == 0x7e && b[3] == 0x80);
}

ATF_TC_WITHOUT_HEAD(error_estimate);
ATF_TC_BODY(error_estimate, tc)
{
	uint16_t	ee;

	ee = stamp_ee_make(true, false, 0.001);
	ATF_CHECK(ee & STAMP_EE_S);
	ATF_CHECK(!(ee & STAMP_EE_Z));
	ATF_CHECK(stamp_ee_seconds(ee) >= 0.001);
	ATF_CHECK(stamp_ee_seconds(ee) < 0.0011);
	ee = stamp_ee_make(false, true, 0);
	ATF_CHECK(!(ee & STAMP_EE_S));
	ATF_CHECK(ee & STAMP_EE_Z);
	ATF_CHECK((ee & 0xff) != 0);
	ee = stamp_ee_make(true, false, 1e9);
	ATF_CHECK((ee & 0xff) != 0);
	ATF_CHECK((stamp_ee_clock() & 0xff) != 0);
	ATF_CHECK(!(stamp_ee_clock() & STAMP_EE_Z));
}

ATF_TC_WITHOUT_HEAD(test_packet);
ATF_TC_BODY(test_packet, tc)
{
	struct stamp_test	t, d;
	uint8_t			p[STAMP_UNAUTH_LEN];
	static const uint8_t	zero[28];

	memset(&t, 0, sizeof(t));
	memset(p, 0xee, sizeof(p));
	t.seq = 0x01020304;
	t.ts.tv_sec = 1778400000;
	t.ts.tv_nsec = 250000000;
	t.ee = 0x8105;
	t.ssid = 0x1234;
	ATF_REQUIRE(stamp_test_encode(p, sizeof(p), &t) == 0);
	ATF_CHECK(p[0] == 1 && p[3] == 4);
	ATF_CHECK(p[12] == 0x81 && p[13] == 0x05);
	ATF_CHECK(p[14] == 0x12 && p[15] == 0x34);
	ATF_CHECK(memcmp(p + 16, zero, sizeof(zero)) == 0);
	ATF_REQUIRE(stamp_test_decode(p, sizeof(p), &d) == 0);
	ATF_CHECK_EQ(d.seq, t.seq);
	ATF_CHECK_EQ(d.ssid, t.ssid);
	ATF_CHECK_EQ(d.ee, t.ee);
	ATF_CHECK_EQ(d.ts.tv_sec, t.ts.tv_sec);
	errno = 0;
	ATF_CHECK(stamp_test_encode(p, 43, &t) == -1 && errno == EMSGSIZE);
	ATF_CHECK(stamp_test_decode(p, 43, &d) == -1);
}

ATF_TC_WITHOUT_HEAD(tlv);
ATF_TC_BODY(tlv, tc)
{
	struct stamp_tlv	v;
	uint8_t			p[64];
	size_t			off = 0;

	memset(p, 0, sizeof(p));
	/* Two TLVs: type 1 of 4 octets, type 8 of 0. */
	p[44] = 0;
	p[45] = 1;
	p[47] = 4;
	memcpy(p + 48, "abcd", 4);
	p[52] = STAMP_TLV_U;
	p[53] = 8;
	ATF_REQUIRE(stamp_tlv_next(p, 56, &off, &v) == 1);
	ATF_CHECK(v.type == 1 && v.len == 4 && memcmp(v.value, "abcd", 4) ==
	    0);
	ATF_REQUIRE(stamp_tlv_next(p, 56, &off, &v) == 1);
	ATF_CHECK(v.type == 8 && v.len == 0 && v.flags == STAMP_TLV_U);
	ATF_CHECK(stamp_tlv_next(p, 56, &off, &v) == 0);
	/* Its length past the packet. */
	off = 0;
	ATF_CHECK(stamp_tlv_next(p, 50, &off, &v) == -1 && errno == EBADMSG);
	off = 0;
	ATF_CHECK(stamp_tlv_next(p, 46, &off, &v) == -1);
}

ATF_TC_WITHOUT_HEAD(reflect_fields);
ATF_TC_BODY(reflect_fields, tc)
{
	struct stamp_refl_conf	c = { .stateful = false, .port = 862 };
	struct stamp_refl	*r;
	struct stamp_reflected	rf;
	struct stamp_test	t;
	struct sockaddr_in	peer = sin4("192.0.2.1", 40000);
	uint8_t			p[STAMP_PKT_MAX], out[STAMP_PKT_MAX];
	enum stamp_drop		why;
	ssize_t			n;

	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	pkt_make(p, 44, 7, 4660);
	ATF_REQUIRE(stamp_test_decode(p, 44, &t) == 0);
	n = reply(r, p, 44, (struct sockaddr *)&peer, NULL, 0, 0, out, &why);
	ATF_REQUIRE_EQ(n, 44);
	ATF_CHECK_EQ(why, STAMP_ANSWERED);
	ATF_REQUIRE(stamp_reflected_decode(out, (size_t)n, &rf) == 0);
	ATF_CHECK_EQ(rf.seq, 7);
	ATF_CHECK_EQ(rf.sseq, 7);
	ATF_CHECK_EQ(rf.ssid, 4660);
	ATF_CHECK_EQ(rf.sttl, 77);
	ATF_CHECK_EQ(rf.see, t.ee);
	ATF_CHECK(memcmp(out + 28, p + 4, 10) == 0);
	ATF_CHECK(rf.mbz_ok);
	ATF_CHECK((rf.ee & 0xff) != 0 && !(rf.ee & STAMP_EE_Z));
	/* The Timestamp is the caller's, set last. */
	stamp_refl_send_time(out, &rf.rx);
	ATF_REQUIRE(stamp_reflected_decode(out, (size_t)n, &rf) == 0);
	ATF_CHECK(stamp_ts_sub(&rf.ts, &rf.rx) == 0);
	/* Longer: exactly as long, what follows the base copied. */
	pkt_make(p, 200, 8, 1);
	n = reply(r, p, 200, (struct sockaddr *)&peer, NULL, 0, 0, out, &why);
	ATF_REQUIRE_EQ(n, 200);
	ATF_CHECK(memcmp(out + 44, p + 44, 156) == 0);
	n = reply(r, p, 45, (struct sockaddr *)&peer, NULL, 0, 0, out, &why);
	ATF_CHECK_EQ(n, 45);
	stamp_refl_free(r);
}

ATF_TC_WITHOUT_HEAD(reflect_short);
ATF_TC_BODY(reflect_short, tc)
{
	struct stamp_refl_conf	c = { .stateful = true, .port = 862 };
	struct stamp_refl	*r;
	struct stamp_refl_stats	st;
	struct sockaddr_in	peer = sin4("192.0.2.1", 40000);
	uint8_t			p[STAMP_PKT_MAX], out[STAMP_PKT_MAX];
	enum stamp_drop		why;
	size_t			lens[] = { 43, 14, 13, 0 };

	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	pkt_make(p, 44, 1, 1);
	for (size_t i = 0; i < nitems(lens); i++) {
		ATF_CHECK_EQ(reply(r, p, lens[i], (struct sockaddr *)&peer,
		    NULL, 0, 0, out, &why), -1);
		ATF_CHECK_EQ(why, STAMP_DROP_SHORT);
	}
	stamp_refl_stats(r, &st);
	ATF_CHECK_EQ(st.dropped[STAMP_DROP_SHORT], 4);
	/* None of them counted in the session. */
	ATF_CHECK_EQ(st.sessions, 0);
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&peer, NULL, 0, 0, out,
	    &why) == 44);
	ATF_CHECK_EQ(seq_of(out), 0);
	stamp_refl_free(r);
}

ATF_TC_WITHOUT_HEAD(reflect_port);
ATF_TC_BODY(reflect_port, tc)
{
	struct stamp_refl_conf	c = { .port = 862 };
	struct stamp_refl	*r;
	struct sockaddr_in	p0 = sin4("192.0.2.1", 0);
	struct sockaddr_in	p862 = sin4("192.0.2.1", 862);
	uint8_t			p[STAMP_PKT_MAX], out[STAMP_PKT_MAX];
	enum stamp_drop		why;

	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	pkt_make(p, 44, 1, 1);
	ATF_CHECK_EQ(reply(r, p, 44, (struct sockaddr *)&p0, NULL, 0, 0, out,
	    &why), -1);
	ATF_CHECK_EQ(why, STAMP_DROP_PORT);
	ATF_CHECK_EQ(reply(r, p, 44, (struct sockaddr *)&p862, NULL, 0, 0, out,
	    &why), -1);
	ATF_CHECK_EQ(why, STAMP_DROP_PORT);
	stamp_refl_free(r);
}

ATF_TC_WITHOUT_HEAD(reflect_stateful);
ATF_TC_BODY(reflect_stateful, tc)
{
	struct stamp_refl_conf	c = { .stateful = true, .port = 862 };
	struct stamp_refl	*r;
	struct stamp_refl_stats	st;
	struct sockaddr_in	a = sin4("192.0.2.1", 40000);
	struct sockaddr_in	a2 = sin4("192.0.2.1", 40001);
	struct sockaddr_in	l1 = sin4("198.51.100.1", 0);
	struct sockaddr_in	l2 = sin4("198.51.100.2", 0);
	struct sockaddr_in6	b = sin6("2001:db8::1", 40000);
	uint8_t			p[STAMP_PKT_MAX], out[STAMP_PKT_MAX];
	struct sockaddr		*pa = (struct sockaddr *)&a;
	uint32_t		i;

	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	/* 0, 1, 2 whatever the sender counts. */
	for (i = 0; i < 3; i++) {
		pkt_make(p, 44, 500 + i, 1);
		ATF_REQUIRE(reply(r, p, 44, pa, (struct sockaddr *)&l1, 0, 10,
		    out, NULL) == 44);
		ATF_CHECK_EQ(seq_of(out), i);
	}
	/* Another SSID, port, local address, tag, family: their own. */
	pkt_make(p, 44, 9, 2);
	ATF_REQUIRE(reply(r, p, 44, pa, (struct sockaddr *)&l1, 0, 10, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 0);
	pkt_make(p, 44, 9, 1);
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&a2,
	    (struct sockaddr *)&l1, 0, 10, out, NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 0);
	ATF_REQUIRE(reply(r, p, 44, pa, (struct sockaddr *)&l2, 0, 10, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 0);
	ATF_REQUIRE(reply(r, p, 44, pa, (struct sockaddr *)&l1, 1, 10, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 0);
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&b, NULL, 0, 10, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 0);
	/* The first goes on from 3. */
	ATF_REQUIRE(reply(r, p, 44, pa, (struct sockaddr *)&l1, 0, 10, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 3);
	stamp_refl_stats(r, &st);
	ATF_CHECK_EQ(st.sessions, 6);
	/* Idle past sess_idle: ended, from 0 again. */
	stamp_refl_expire(r, 10 + STAMP_SESS_IDLE + 1);
	stamp_refl_stats(r, &st);
	ATF_CHECK_EQ(st.sessions, 0);
	ATF_REQUIRE(reply(r, p, 44, pa, (struct sockaddr *)&l1, 0, 400, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 0);
	/* Stateless: the sender's number. */
	c.stateful = false;
	ATF_REQUIRE(stamp_refl_setconf(r, &c) == 0);
	ATF_REQUIRE(reply(r, p, 44, pa, (struct sockaddr *)&l1, 0, 400, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 9);
	stamp_refl_free(r);
}

ATF_TC_WITHOUT_HEAD(reflect_sessions_max);
ATF_TC_BODY(reflect_sessions_max, tc)
{
	struct stamp_refl_conf	c = { .stateful = true, .sess_max = 2 };
	struct stamp_refl	*r;
	struct sockaddr_in	a = sin4("192.0.2.1", 1);
	struct sockaddr_in	b = sin4("192.0.2.2", 1);
	struct sockaddr_in	d = sin4("192.0.2.3", 1);
	uint8_t			p[STAMP_PKT_MAX], out[STAMP_PKT_MAX];

	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	pkt_make(p, 44, 1, 1);
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&a, NULL, 0, 1, out,
	    NULL) == 44);
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&a, NULL, 0, 1, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 1);
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&b, NULL, 0, 2, out,
	    NULL) == 44);
	/* A third: the oldest (a's) replaced. */
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&d, NULL, 0, 3, out,
	    NULL) == 44);
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&b, NULL, 0, 4, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 1);
	ATF_REQUIRE(reply(r, p, 44, (struct sockaddr *)&a, NULL, 0, 5, out,
	    NULL) == 44);
	ATF_CHECK_EQ(seq_of(out), 0);
	stamp_refl_free(r);
}

ATF_TC_WITHOUT_HEAD(reflect_rate);
ATF_TC_BODY(reflect_rate, tc)
{
	struct stamp_refl_conf	c = { .rate = 2, .burst = 4 };
	struct stamp_refl	*r;
	struct stamp_refl_stats	st;
	struct sockaddr_in	a = sin4("192.0.2.1", 40000);
	struct sockaddr_in6	b = sin6("2001:db8::1", 40000);
	uint8_t			p[STAMP_PKT_MAX], out[STAMP_PKT_MAX];
	enum stamp_drop		why;
	int			i, n;

	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	pkt_make(p, 44, 1, 1);
	/* A burst of 10 at once: the bucket's 4. */
	for (i = n = 0; i < 10; i++)
		if (reply(r, p, 44, (struct sockaddr *)&a, NULL, 0, 100, out,
		    &why) == 44)
			n++;
		else
			ATF_CHECK_EQ(why, STAMP_DROP_RATE);
	ATF_CHECK_EQ(n, 4);
	/* Another source: a bucket of its own. */
	ATF_CHECK(reply(r, p, 44, (struct sockaddr *)&b, NULL, 0, 100, out,
	    NULL) == 44);
	/* A second later, 2 more. */
	for (i = n = 0; i < 10; i++)
		if (reply(r, p, 44, (struct sockaddr *)&a, NULL, 0, 101, out,
		    NULL) == 44)
			n++;
	ATF_CHECK_EQ(n, 2);
	stamp_refl_stats(r, &st);
	ATF_CHECK_EQ(st.dropped[STAMP_DROP_RATE], 14);
	ATF_CHECK_EQ(st.answered, 7);
	/* All of them, 3 a second, whatever each may. */
	c.rate = 0;
	c.rate_total = 3;
	ATF_REQUIRE(stamp_refl_setconf(r, &c) == 0);
	for (i = n = 0; i < 10; i++) {
		struct sockaddr_in	s = sin4("203.0.113.1", 1000);

		s.sin_addr.s_addr = htonl(0xcb007100 + (uint32_t)i);
		if (reply(r, p, 44, (struct sockaddr *)&s, NULL, 0, 200, out,
		    NULL) == 44)
			n++;
	}
	ATF_CHECK_EQ(n, 3);
	/* No limit. */
	c.rate_total = 0;
	ATF_REQUIRE(stamp_refl_setconf(r, &c) == 0);
	for (i = n = 0; i < 100; i++)
		if (reply(r, p, 44, (struct sockaddr *)&a, NULL, 0, 300, out,
		    NULL) == 44)
			n++;
	ATF_CHECK_EQ(n, 100);
	stamp_refl_free(r);
}

/* ---- The sender against the reflector's core, in process ---------- */

/*
 * A packet of the sender's sent at mono, reflected by r (its T2 at
 * mono's time of day and T3 refl seconds later): the reply into out,
 * its length; 0 when drop says the way out lost it.
 */
static ssize_t
sendrefl(struct stamp_sender *s, struct stamp_refl *r, double mono,
    double refl, bool drop, uint8_t *out, int *lostrc)
{
	struct stamp_sample	 sm;
	struct sockaddr_in	 a = sin4("192.0.2.1", 40000);
	struct stamp_rx		 rx;
	struct timespec		 t1, t3;
	uint8_t			 p[STAMP_UNAUTH_LEN];
	ssize_t			 n;
	int			 rc;

	t1.tv_sec = 1778400000 + (time_t)mono;
	t1.tv_nsec = (long)((mono - (double)(time_t)mono) * 1e9);
	rc = stamp_sender_packet(s, p, sizeof(p), &t1, mono, &sm);
	ATF_REQUIRE(rc != -1);
	if (lostrc != NULL)
		*lostrc = rc;
	if (drop)
		return (0);
	memset(&rx, 0, sizeof(rx));
	rx.pkt = p;
	rx.len = sizeof(p);
	rx.peer = (struct sockaddr *)&a;
	rx.ttl = 64;
	rx.t2 = t1;		/* the reflector's clock: any */
	rx.t2.tv_sec += 5;
	rx.mono = mono;
	ATF_REQUIRE((n = stamp_refl_reply(r, &rx, out, STAMP_PKT_MAX, NULL)) ==
	    STAMP_UNAUTH_LEN);
	t3 = rx.t2;
	t3.tv_nsec += (long)(refl * 1e9);
	if (t3.tv_nsec >= 1000000000) {
		t3.tv_sec++;
		t3.tv_nsec -= 1000000000;
	}
	stamp_refl_send_time(out, &t3);
	return (n);
}

ATF_TC_WITHOUT_HEAD(sender_rtt);
ATF_TC_BODY(sender_rtt, tc)
{
	struct stamp_sender_conf  c = { .ssid = 7, .timeout = 1 };
	struct stamp_refl_conf	  rc = { .stateful = false, .port = 862 };
	struct stamp_sender	 *s;
	struct stamp_refl	 *r;
	struct stamp_sender_stats st;
	struct stamp_sample	  sm;
	uint8_t			  out[STAMP_PKT_MAX];

	ATF_REQUIRE((s = stamp_sender_new(&c)) != NULL);
	ATF_REQUIRE((r = stamp_refl_new(&rc)) != NULL);
	/* 50 ms there and back, 10 of them the reflector's own. */
	ATF_REQUIRE(sendrefl(s, r, 100, 0.010, false, out, NULL) > 0);
	ATF_CHECK_EQ(stamp_sender_next(s), 101);
	ATF_REQUIRE(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 100.050,
	    NULL, &sm) == 1);
	ATF_CHECK(!sm.lost);
	ATF_CHECK_MSG(sm.rtt > 0.0399 && sm.rtt < 0.0401, "rtt %g", sm.rtt);
	ATF_CHECK_MSG(sm.refl > 0.0099 && sm.refl < 0.0101, "refl %g",
	    sm.refl);
	ATF_CHECK_EQ(sm.r.ssid, 7);
	ATF_CHECK_EQ(sm.r.sttl, 64);
	ATF_CHECK_EQ(stamp_sender_next(s), 0);
	/* The same reply again; another session's; garbage. */
	ATF_CHECK(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 100.06,
	    NULL, &sm) == 0);
	out[15] = 8;
	ATF_CHECK(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 100.06,
	    NULL, &sm) == 0);
	ATF_CHECK(stamp_sender_reply(s, out, 43, 100.06, NULL, &sm) == -1);
	/* The reflector's clock says more than the round trip: 0. */
	ATF_REQUIRE(sendrefl(s, r, 101, 0.5, false, out, NULL) > 0);
	ATF_REQUIRE(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 101.1,
	    NULL, &sm) == 1);
	ATF_CHECK_EQ(sm.rtt, 0);
	stamp_sender_stats(s, &st);
	ATF_CHECK_EQ(st.sent, 2);
	ATF_CHECK_EQ(st.received, 2);
	ATF_CHECK_EQ(st.late, 1);
	ATF_CHECK_EQ(st.foreign, 1);
	ATF_CHECK_EQ(st.mode, STAMP_MODE_STATELESS);
	stamp_sender_free(s);
	stamp_refl_free(r);
}

/*
 * 20 packets; out lost on the way out, back on the way back (and one
 * of those coming after its timeout): the loss each way from a
 * stateful reflector, the round trip's alone from a stateless one.
 */
static void
loss_run(bool stateful, struct stamp_sender_stats *st)
{
	static const bool	  out_lost[20] = { [3] = true, [4] = true,
	    [10] = true };
	static const bool	  back_lost[20] = { [6] = true, [12] = true,
	    [13] = true };
	struct stamp_sender_conf  c = { .ssid = 1, .timeout = 1 };
	struct stamp_refl_conf	  rc = { .port = 862 };
	struct stamp_sender	 *s;
	struct stamp_refl	 *r;
	struct stamp_sample	  sm;
	uint8_t			  out[STAMP_PKT_MAX], late[STAMP_PKT_MAX];
	double			  t;
	int			  i, lost = 0;

	rc.stateful = stateful;
	ATF_REQUIRE((s = stamp_sender_new(&c)) != NULL);
	ATF_REQUIRE((r = stamp_refl_new(&rc)) != NULL);
	for (i = 0; i < 20; i++) {
		t = 10 + i * 0.1;
		while (stamp_sender_expire(s, t, &sm) == 1) {
			ATF_CHECK(sm.lost);
			lost++;
		}
		if (sendrefl(s, r, t, 0.001, out_lost[i], i == 12 ? late :
		    out, NULL) == 0 || back_lost[i])
			continue;
		ATF_REQUIRE(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, t +
		    0.02, NULL, &sm) == 1);
	}
	while (stamp_sender_expire(s, 100, &sm) == 1)
		lost++;
	ATF_CHECK_EQ(lost, 6);
	/* 12's reply, after its timeout: late, still lost. */
	ATF_CHECK(stamp_sender_reply(s, late, STAMP_UNAUTH_LEN, 100,
	    NULL, &sm) == 0);
	stamp_sender_stats(s, st);
	ATF_CHECK_EQ(st->late, 1);
	stamp_sender_free(s);
	stamp_refl_free(r);
}

ATF_TC_WITHOUT_HEAD(sender_loss_stateful);
ATF_TC_BODY(sender_loss_stateful, tc)
{
	struct stamp_sender_stats st;

	loss_run(true, &st);
	ATF_CHECK_EQ(st.mode, STAMP_MODE_STATEFUL);
	ATF_CHECK_EQ(st.sent, 20);
	ATF_CHECK_EQ(st.received, 14);
	ATF_CHECK_EQ(st.lost, 6);
	ATF_CHECK_EQ(st.fwd_lost, 3);
	ATF_CHECK_EQ(st.back_lost, 3);
	ATF_CHECK_EQ(st.unknown_lost, 0);
}

ATF_TC_WITHOUT_HEAD(sender_loss_stateless);
ATF_TC_BODY(sender_loss_stateless, tc)
{
	struct stamp_sender_stats st;

	loss_run(false, &st);
	ATF_CHECK_EQ(st.mode, STAMP_MODE_STATELESS);
	ATF_CHECK_EQ(st.received, 14);
	ATF_CHECK_EQ(st.lost, 6);
	ATF_CHECK_EQ(st.fwd_lost, 0);
	ATF_CHECK_EQ(st.back_lost, 0);
	ATF_CHECK_EQ(st.unknown_lost, 6);
}

ATF_TC_WITHOUT_HEAD(sender_window);
ATF_TC_BODY(sender_window, tc)
{
	struct stamp_sender_conf  c = { .ssid = 1, .seq_set = true,
	    .seq0 = 0xfffffffe, .window = 4 };
	struct stamp_refl_conf	  rc = { .stateful = true, .port = 862 };
	struct stamp_sender	 *s;
	struct stamp_refl	 *r;
	struct stamp_sender_stats st;
	struct stamp_sample	  sm;
	uint8_t			  out[STAMP_PKT_MAX];
	int			  i, rcl;

	ATF_REQUIRE((s = stamp_sender_new(&c)) != NULL);
	ATF_REQUIRE((r = stamp_refl_new(&rc)) != NULL);
	/* Six in flight in a window of four, across the wrap of the
	 * numbers: the two oldest given up. */
	for (i = 0; i < 6; i++) {
		ATF_REQUIRE(sendrefl(s, r, 1 + i * 0.01, 0, true, out, &rcl) ==
		    0);
		ATF_CHECK_EQ(rcl, i >= 4 ? 1 : 0);
	}
	stamp_sender_stats(s, &st);
	ATF_CHECK_EQ(st.lost, 2);
	/* The seventh (sequence 4, 0xfffffffe + 6) gives up 0 and is
	 * answered, the reflector's first: those before it not told
	 * apart, there being no reply before them. */
	ATF_REQUIRE(sendrefl(s, r, 2, 0, false, out, &rcl) > 0);
	ATF_CHECK_EQ(rcl, 1);
	ATF_REQUIRE(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 2.01,
	    NULL, &sm) == 1);
	ATF_CHECK_EQ(sm.seq, 4);
	ATF_CHECK_EQ(sm.r.seq, 0);
	ATF_CHECK(stamp_sender_expire(s, 2.5, &sm) == 0);
	ATF_CHECK(stamp_sender_expire(s, 4, &sm) == 1);
	ATF_CHECK_EQ(sm.seq, 1);
	ATF_CHECK(stamp_sender_expire(s, 4, &sm) == 1);
	ATF_CHECK(stamp_sender_expire(s, 4, &sm) == 1);
	ATF_CHECK_EQ(sm.seq, 3);
	ATF_CHECK(stamp_sender_expire(s, 4, &sm) == 0);
	ATF_CHECK_EQ(stamp_sender_next(s), 0);
	stamp_sender_stats(s, &st);
	ATF_CHECK_EQ(st.mode, STAMP_MODE_STATEFUL);
	ATF_CHECK_EQ(st.lost, 6);
	ATF_CHECK_EQ(st.unknown_lost, 6);
	ATF_CHECK_EQ(st.fwd_lost + st.back_lost, 0);
	stamp_sender_free(s);
	stamp_refl_free(r);
}

ATF_TC_WITHOUT_HEAD(sender_restart);
ATF_TC_BODY(sender_restart, tc)
{
	struct stamp_sender_conf  c = { .ssid = 1, .timeout = 1 };
	struct stamp_refl_conf	  rc = { .stateful = true, .port = 862 };
	struct stamp_sender	 *s;
	struct stamp_refl	 *r;
	struct stamp_sender_stats st;
	struct stamp_sample	  sm;
	uint8_t			  out[STAMP_PKT_MAX];
	int			  i;

	ATF_REQUIRE((s = stamp_sender_new(&c)) != NULL);
	ATF_REQUIRE((r = stamp_refl_new(&rc)) != NULL);
	for (i = 0; i < 5; i++) {
		ATF_REQUIRE(sendrefl(s, r, 1 + i, 0, false, out, NULL) > 0);
		ATF_REQUIRE(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 1.01 +
		    i, NULL, &sm) == 1);
	}
	/* One lost, and the reflector started again: its counter from 0,
	 * the gap not told apart. */
	(void)sendrefl(s, r, 6, 0, true, out, NULL);
	stamp_refl_free(r);
	ATF_REQUIRE((r = stamp_refl_new(&rc)) != NULL);
	ATF_REQUIRE(sendrefl(s, r, 7, 0, false, out, NULL) > 0);
	ATF_CHECK(stamp_sender_expire(s, 7.5, &sm) == 1);
	ATF_REQUIRE(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 7.01,
	    NULL, &sm) == 1);
	stamp_sender_stats(s, &st);
	ATF_CHECK_EQ(st.lost, 1);
	ATF_CHECK_EQ(st.unknown_lost, 1);
	ATF_CHECK_EQ(st.fwd_lost + st.back_lost, 0);
	/* From there on, told apart again. */
	(void)sendrefl(s, r, 8, 0, true, out, NULL);
	ATF_REQUIRE(sendrefl(s, r, 9, 0, false, out, NULL) > 0);
	ATF_CHECK(stamp_sender_expire(s, 9.5, &sm) == 1);
	ATF_REQUIRE(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 9.01,
	    NULL, &sm) == 1);
	stamp_sender_stats(s, &st);
	ATF_CHECK_EQ(st.fwd_lost, 1);
	ATF_CHECK_EQ(st.back_lost, 0);
	stamp_sender_free(s);
	stamp_refl_free(r);
}

ATF_TC_WITHOUT_HEAD(clock_set);
ATF_TC_BODY(clock_set, tc)
{
	struct stamp_clock	c;

	ATF_REQUIRE(stamp_clock_set("ptp:0.000001") == 0);
	stamp_clock_get(&c);
	ATF_CHECK_EQ(c.sync, STAMP_SYNC_PTP);
	ATF_CHECK(c.ee & STAMP_EE_S);
	ATF_CHECK(stamp_ee_seconds(c.ee) >= 0.000001 &&
	    stamp_ee_seconds(c.ee) < 0.0000011);
	ATF_CHECK_EQ(stamp_ee_clock(), c.ee);
	ATF_REQUIRE(stamp_clock_set("gnss") == 0);
	stamp_clock_get(&c);
	ATF_CHECK(c.sync == STAMP_SYNC_GNSS && (c.ee & STAMP_EE_S));
	ATF_CHECK(stamp_ee_seconds(c.ee) < 0.000001);
	/* Free-running: not synchronised. */
	ATF_REQUIRE(stamp_clock_set("local:2") == 0);
	stamp_clock_get(&c);
	ATF_CHECK(c.sync == STAMP_SYNC_LOCAL && !(c.ee & STAMP_EE_S));
	errno = 0;
	ATF_CHECK(stamp_clock_set("sundial") == -1 && errno == EINVAL);
	ATF_CHECK(stamp_clock_set("ntp:") == -1);
	ATF_CHECK(stamp_clock_set("ntp:-1") == -1);
	ATF_CHECK(stamp_clock_set("ntp:1x") == -1);
	/* The kernel's again: ntp or free-running, as it says. */
	ATF_REQUIRE(stamp_clock_set(NULL) == 0);
	stamp_clock_get(&c);
	ATF_CHECK(c.sync == ((c.ee & STAMP_EE_S) ? STAMP_SYNC_NTP :
	    STAMP_SYNC_LOCAL));
	ATF_CHECK_STREQ(stamp_sync_name(STAMP_SYNC_PTP), "ptp");
	ATF_CHECK_STREQ(stamp_sync_name(0), "-");
	ATF_CHECK_STREQ(stamp_sync_name(200), "200");
	ATF_CHECK_STREQ(stamp_tsm_name(STAMP_TSM_HW), "hw");
	ATF_CHECK_STREQ(stamp_tsm_name(STAMP_TSM_CP), "cp");
}

ATF_TC_WITHOUT_HEAD(tlv_tsinfo);
ATF_TC_BODY(tlv_tsinfo, tc)
{
	struct stamp_refl_conf	 c = { .stateful = false, .port = 862 };
	struct stamp_sender_conf sc = { .tsinfo = true };
	struct sockaddr_in	 a = sin4("192.0.2.1", 40000);
	struct stamp_refl	*r;
	struct stamp_sender	*s;
	struct stamp_tsinfo	 ti;
	struct stamp_tlv	 v;
	struct stamp_rx		 rx;
	struct timespec		 t1;
	uint8_t			 p[128], out[STAMP_PKT_MAX];
	size_t			 off;
	int			 i;

	/* Built: the TLV, its value, past the packet refused. */
	memset(p, 0xaa, sizeof(p));
	off = 0;
	ATF_REQUIRE(stamp_tlv_put(p, 52, &off, STAMP_TLV_TSINFO, "\0\0\0\0",
	    4) == 0);
	ATF_CHECK_EQ(off, 52);
	ATF_CHECK(p[44] == 0 && p[45] == 3 && p[46] == 0 && p[47] == 4);
	errno = 0;
	ATF_CHECK(stamp_tlv_put(p, 55, &off, STAMP_TLV_PAD, NULL, 0) == -1 &&
	    errno == EMSGSIZE);
	ATF_REQUIRE(stamp_tlv_put(p, 60, &off, STAMP_TLV_PAD, NULL, 4) == 0);
	ATF_CHECK(p[53] == 1 && p[55] == 4 && p[56] == 0xaa);
	/* Found; one the reflector did not know (U) is none, as none at
	 * all; TLVs past the packet before it, an error. */
	ATF_CHECK(stamp_tsinfo_find(p, 60, &ti) == 1);
	p[44] = STAMP_TLV_U;
	ATF_CHECK(stamp_tsinfo_find(p, 60, &ti) == 0);
	ATF_CHECK(stamp_tsinfo_find(p, 44, &ti) == 0);
	p[44] = 0;
	p[45] = STAMP_TLV_PAD;
	ATF_CHECK(stamp_tsinfo_find(p, 60, &ti) == 0);
	ATF_CHECK(stamp_tsinfo_find(p, 58, &ti) == -1);

	/* The sender's packet: as long as the TLVs need. */
	ATF_REQUIRE((s = stamp_sender_new(&sc)) != NULL);
	ATF_CHECK_EQ(stamp_sender_len(s, 0), 52);
	ATF_CHECK_EQ(stamp_sender_len(s, 44), 52);
	ATF_CHECK_EQ(stamp_sender_len(s, 53), 56);
	ATF_CHECK_EQ(stamp_sender_len(s, 55), 56);
	ATF_CHECK_EQ(stamp_sender_len(s, 100), 100);
	clock_gettime(CLOCK_REALTIME, &t1);
	errno = 0;
	ATF_CHECK(stamp_sender_packet(s, p, 54, &t1, 1, NULL) == -1 &&
	    errno == EMSGSIZE);
	for (i = 0; i < (int)sizeof(p); i++)
		p[i] = (uint8_t)i;
	ATF_REQUIRE(stamp_sender_packet(s, p, 100, &t1, 1, NULL) == 0);
	off = 0;
	ATF_REQUIRE(stamp_tlv_next(p, 100, &off, &v) == 1);
	ATF_CHECK(v.type == STAMP_TLV_TSINFO && v.len == 4 && v.flags == 0);
	ATF_CHECK(v.value[0] == 0 && v.value[3] == 0);
	ATF_REQUIRE(stamp_tlv_next(p, 100, &off, &v) == 1);
	ATF_CHECK(v.type == STAMP_TLV_PAD && v.len == 44 && v.value[0] == 56);
	ATF_CHECK(stamp_tlv_next(p, 100, &off, &v) == 0);

	/* Reflected: filled, the hardware's T2, an unknown TLV marked,
	 * the padding as it was; the reply as long. */
	p[56] = 0;		/* an unknown TLV inside the padding's room */
	p[57] = 99;
	p[58] = 0;
	p[59] = 40;
	p[53] = STAMP_TLV_PAD;
	p[55] = 0;
	ATF_REQUIRE(stamp_clock_set("ptp:0.000001") == 0);
	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	memset(&rx, 0, sizeof(rx));
	rx.pkt = p;
	rx.len = 100;
	rx.peer = (struct sockaddr *)&a;
	rx.t2 = t1;
	rx.mono = 1;
	rx.ts_in = STAMP_TSM_HW;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	ATF_REQUIRE(stamp_tsinfo_find(out, 100, &ti) == 1);
	ATF_CHECK_EQ(ti.sync_in, STAMP_SYNC_PTP);
	ATF_CHECK_EQ(ti.ts_in, STAMP_TSM_HW);
	ATF_CHECK_EQ(ti.sync_out, STAMP_SYNC_PTP);
	ATF_CHECK_EQ(ti.ts_out, STAMP_TSM_SW);
	ATF_CHECK(out[52] == 0 && out[53] == STAMP_TLV_PAD);
	ATF_CHECK(out[56] == STAMP_TLV_U && out[57] == 99);
	ATF_CHECK(memcmp(out + 60, p + 60, 40) == 0);
	stamp_refl_free(r);

	/* Padding, not TLVs (a type 0, a length past the end): copied. */
	c.ts_out = STAMP_TSM_CP;
	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	for (i = 44; i < 100; i++)
		p[i] = 0;
	p[45] = STAMP_TLV_TSINFO;
	p[47] = 4;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	ATF_CHECK(memcmp(out + 44, p + 44, 56) == 0);
	p[53] = 99;
	p[55] = 60;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	ATF_CHECK(memcmp(out + 44, p + 44, 56) == 0);
	/* The TLV alone: filled, T3 the control plane's. */
	ATF_REQUIRE(stamp_refl_reply(r, &(struct stamp_rx){ .pkt = p, .len = 52,
	    .peer = (struct sockaddr *)&a, .t2 = t1, .mono = 1 }, out,
	    sizeof(out), NULL) == 52);
	ATF_REQUIRE(stamp_tsinfo_find(out, 52, &ti) == 1);
	ATF_CHECK(ti.ts_in == STAMP_TSM_SW && ti.ts_out == STAMP_TSM_CP);
	stamp_refl_free(r);
	stamp_sender_free(s);
	stamp_clock_set(NULL);
}

/*
 * A packet of a sender asking for the Timestamp Information TLV, both
 * clocks as clk says (the process's: the sender's and the reflector's
 * the same), 30 ms out, 10 the reflector's, 5 back: its sample.
 */
static void
owd_run(const char *clk, struct stamp_sample *sm)
{
	struct stamp_sender_conf sc = { .ssid = 9, .tsinfo = true };
	struct stamp_refl_conf	 rc = { .stateful = true, .port = 862 };
	struct sockaddr_in	 a = sin4("192.0.2.1", 40000);
	struct stamp_sender	*s;
	struct stamp_refl	*r;
	struct stamp_rx		 rx;
	struct timespec		 t1, t3, t4;
	uint8_t			 p[64], out[STAMP_PKT_MAX];

	ATF_REQUIRE(stamp_clock_set(clk) == 0);
	ATF_REQUIRE((s = stamp_sender_new(&sc)) != NULL);
	ATF_REQUIRE((r = stamp_refl_new(&rc)) != NULL);
	t1.tv_sec = 1778400100;
	t1.tv_nsec = 0;
	ATF_REQUIRE(stamp_sender_packet(s, p, 52, &t1, 100, NULL) == 0);
	memset(&rx, 0, sizeof(rx));
	rx.pkt = p;
	rx.len = 52;
	rx.peer = (struct sockaddr *)&a;
	rx.t2 = t1;
	rx.t2.tv_nsec = 30000000;
	rx.mono = 100.03;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 52);
	t3 = rx.t2;
	t3.tv_nsec = 40000000;
	stamp_refl_send_time(out, &t3);
	t4 = t1;
	t4.tv_nsec = 45000000;
	ATF_REQUIRE(stamp_sender_reply(s, out, 52, 100.045, &t4, sm) == 1);
	ATF_CHECK_MSG(sm->rtt > 0.0349 && sm->rtt < 0.0351, "rtt %g", sm->rtt);
	ATF_CHECK(sm->has_tsinfo);
	stamp_refl_free(r);
	stamp_sender_free(s);
	stamp_clock_set(NULL);
}

ATF_TC_WITHOUT_HEAD(sender_owd);
ATF_TC_BODY(sender_owd, tc)
{
	struct stamp_sample	sm;

	/* Both synchronised, within a microsecond: one way each. */
	owd_run("ptp:0.000001", &sm);
	ATF_CHECK(sm.owd);
	ATF_CHECK_MSG(sm.fwd > 0.0299 && sm.fwd < 0.0301, "fwd %g", sm.fwd);
	ATF_CHECK_MSG(sm.back > 0.0049 && sm.back < 0.0051, "back %g",
	    sm.back);
	ATF_CHECK(sm.err > 0.000002 && sm.err < 0.0000022);
	ATF_CHECK_EQ(sm.tsinfo.sync_in, STAMP_SYNC_PTP);
	ATF_CHECK_EQ(sm.tsinfo.ts_out, STAMP_TSM_SW);
	/* Free-running: half the round trip each, an estimate. */
	owd_run("local:0.000001", &sm);
	ATF_CHECK(!sm.owd);
	ATF_CHECK_MSG(sm.fwd > 0.0174 && sm.fwd < 0.0176, "fwd %g", sm.fwd);
	ATF_CHECK_EQ(sm.fwd, sm.back);
	ATF_CHECK_EQ(sm.tsinfo.sync_in, STAMP_SYNC_LOCAL);
	/* Synchronised, but 2 ms of error is more than a tenth of the
	 * 17.5 ms each way; 0.8 ms is not. */
	owd_run("ntp:0.001", &sm);
	ATF_CHECK(!sm.owd);
	ATF_CHECK_EQ(sm.fwd, sm.rtt / 2);
	owd_run("ntp:0.0008", &sm);
	ATF_CHECK(sm.owd);
}

ATF_TC_WITHOUT_HEAD(sender_owd_bounds);
ATF_TC_BODY(sender_owd_bounds, tc)
{
	struct stamp_sender_conf sc = { .ssid = 9, .owd_frac = 0.5 };
	struct stamp_refl_conf	 rc = { .stateful = false, .port = 862 };
	struct sockaddr_in	 a = sin4("192.0.2.1", 40000);
	struct stamp_sender	*s;
	struct stamp_refl	*r;
	struct stamp_sample	 sm;
	struct stamp_rx		 rx;
	struct timespec		 t1, t4;
	uint8_t			 p[STAMP_UNAUTH_LEN], out[STAMP_PKT_MAX];
	int			 i;

	ATF_REQUIRE(stamp_clock_set("ntp:0.001") == 0);
	ATF_REQUIRE((s = stamp_sender_new(&sc)) != NULL);
	ATF_REQUIRE((r = stamp_refl_new(&rc)) != NULL);
	for (i = 0; i < 3; i++) {
		t1.tv_sec = 1778400200 + i;
		t1.tv_nsec = 0;
		ATF_REQUIRE(stamp_sender_packet(s, p, sizeof(p), &t1, 200 + i,
		    NULL) == 0);
		memset(&rx, 0, sizeof(rx));
		rx.pkt = p;
		rx.len = sizeof(p);
		rx.peer = (struct sockaddr *)&a;
		rx.mono = 200 + i;
		/* The reflector's clock 1 s behind (i 1): the way out
		 * negative; the reply's time of day unknown (i 2). */
		rx.t2 = t1;
		rx.t2.tv_nsec = 10000000;
		if (i == 1)
			rx.t2.tv_sec--;
		ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) ==
		    STAMP_UNAUTH_LEN);
		stamp_refl_send_time(out, &rx.t2);
		t4 = t1;
		t4.tv_nsec = 20000000;
		ATF_REQUIRE(stamp_sender_reply(s, out, STAMP_UNAUTH_LEN, 200 +
		    i + 0.02, i == 2 ? NULL : &t4, &sm) == 1);
		/* No TLV asked for: none. */
		ATF_CHECK(!sm.has_tsinfo);
		/* 2 ms of error within half of the 10 ms each way. */
		ATF_CHECK_MSG(sm.owd == (i == 0), "%d: owd %d", i, sm.owd);
		ATF_CHECK_MSG(sm.fwd > 0.0099 && sm.fwd < 0.0101, "%d: fwd %g",
		    i, sm.fwd);
	}
	stamp_refl_free(r);
	stamp_sender_free(s);
	stamp_clock_set(NULL);
}

/*
 * The Class of Service TLV (RFC 8972 4.4): the sender's DSCP1; the
 * reflector's DSCP2 and ECN as the request came, the reply to carry
 * DSCP1, or, refused, the request's DSCP and RP 1; malformed when not
 * 4 octets; no TOS known: DSCP2 0, the socket's own.
 */
ATF_TC_WITHOUT_HEAD(tlv_cos);
ATF_TC_BODY(tlv_cos, tc)
{
	struct stamp_refl_conf	 c = { .stateful = false, .port = 862 };
	struct stamp_sender_conf sc = { .cos = true, .dscp = 46, .ssid = 3 };
	struct sockaddr_in	 a = sin4("192.0.2.1", 40000);
	struct stamp_refl	*r;
	struct stamp_sender	*s;
	struct stamp_sample	 sm;
	struct stamp_cos	 co;
	struct stamp_tlv	 v;
	struct stamp_rx		 rx;
	struct timespec		 t1;
	uint8_t			 p[128], out[STAMP_PKT_MAX];
	size_t			 off;

	ATF_REQUIRE((s = stamp_sender_new(&sc)) != NULL);
	ATF_CHECK_EQ(stamp_sender_len(s, 0), 52);
	sc.tsinfo = true;
	stamp_sender_free(s);
	ATF_REQUIRE((s = stamp_sender_new(&sc)) != NULL);
	ATF_CHECK_EQ(stamp_sender_len(s, 0), 60);
	ATF_CHECK_EQ(stamp_sender_len(s, 61), 64);
	clock_gettime(CLOCK_REALTIME, &t1);
	ATF_REQUIRE(stamp_sender_packet(s, p, 80, &t1, 1, NULL) == 0);
	off = 0;
	ATF_REQUIRE(stamp_tlv_next(p, 80, &off, &v) == 1);
	ATF_CHECK(v.type == STAMP_TLV_TSINFO);
	ATF_REQUIRE(stamp_tlv_next(p, 80, &off, &v) == 1);
	ATF_CHECK(v.type == STAMP_TLV_COS && v.len == 4 && v.flags == 0);
	ATF_CHECK(v.value[0] == 46 << 2 && v.value[1] == 0 &&
	    v.value[2] == 0 && v.value[3] == 0);
	ATF_REQUIRE(stamp_tlv_next(p, 80, &off, &v) == 1);
	ATF_CHECK(v.type == STAMP_TLV_PAD && v.len == 16);
	/* Not reflected yet: DSCP1 alone, RP 0. */
	ATF_REQUIRE(stamp_cos_find(p, 80, &co) == 1);
	ATF_CHECK(co.dscp1 == 46 && co.dscp2 == 0 && co.rp == 0);

	/* Reflected: it came with DSCP 10 and ECN 1 (an ipfw setdscp on
	 * the way, say); the reply to carry 46. */
	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	ATF_CHECK_EQ(stamp_refl_reply_tos(r), -1);
	memset(&rx, 0, sizeof(rx));
	rx.pkt = p;
	rx.len = 80;
	rx.peer = (struct sockaddr *)&a;
	rx.t2 = t1;
	rx.mono = 1;
	rx.tos = 10 << 2 | 1;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 80);
	ATF_CHECK_EQ(stamp_refl_reply_tos(r), 46 << 2);
	ATF_REQUIRE(stamp_cos_find(out, 80, &co) == 1);
	ATF_CHECK_EQ(co.dscp1, 46);
	ATF_CHECK_EQ(co.dscp2, 10);
	ATF_CHECK_EQ(co.ecn, 1);
	ATF_CHECK_EQ(co.rp, 0);
	ATF_REQUIRE(stamp_sender_reply(s, out, 80, 1.01, NULL, &sm) == 1);
	ATF_CHECK(sm.has_cos && sm.has_tsinfo);
	ATF_CHECK(sm.cos.dscp2 == 10 && sm.cos.rp == 0);

	/* Refused (46 among dscp_deny): the request's DSCP, RP 1. */
	c.dscp_deny = (uint64_t)1 << 46;
	ATF_REQUIRE(stamp_refl_setconf(r, &c) == 0);
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 80);
	ATF_CHECK_EQ(stamp_refl_reply_tos(r), 10 << 2);
	ATF_REQUIRE(stamp_cos_find(out, 80, &co) == 1);
	ATF_CHECK(co.dscp1 == 46 && co.dscp2 == 10 && co.rp == 1);
	/* ... and the TOS it came with not known: the socket's own. */
	rx.tos = -1;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 80);
	ATF_CHECK_EQ(stamp_refl_reply_tos(r), -1);
	ATF_REQUIRE(stamp_cos_find(out, 80, &co) == 1);
	ATF_CHECK(co.dscp2 == 0 && co.ecn == 0 && co.rp == 1);

	/* Not 4 octets: malformed, none found; nothing asked of the
	 * reply's TOS. */
	p[55] = 5;
	off = 52;
	ATF_REQUIRE(stamp_tlv_next(p, 80, &off, &v) == 1);
	ATF_REQUIRE(v.type == STAMP_TLV_COS && v.len == 5);
	/* What follows it: a TLV again to the end. */
	ATF_REQUIRE(stamp_tlv_put(p, 80, &off, STAMP_TLV_PAD, NULL,
	    (uint16_t)(80 - off - STAMP_TLV_HDR)) == 0);
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 80);
	ATF_CHECK_EQ(stamp_refl_reply_tos(r), -1);
	ATF_CHECK(out[52] == STAMP_TLV_M);
	ATF_CHECK(stamp_cos_find(out, 80, &co) == 0);
	/* No TLV: the socket's own. */
	ATF_REQUIRE(reply(r, p, STAMP_UNAUTH_LEN, (struct sockaddr *)&a, NULL,
	    0, 2, out, NULL) == STAMP_UNAUTH_LEN);
	ATF_CHECK_EQ(stamp_refl_reply_tos(r), -1);
	stamp_refl_free(r);
	stamp_sender_free(s);
}

/*
 * The Direct Measurement TLV (RFC 8972 4.5): the sender's counter; a
 * stateful reflector's received and sent in the session (one over the
 * rate received, not sent), a stateless one's 0, not counted; the loss
 * each way by them, a reordered reply passed over, a reflector started
 * again a new start.  Malformed when not 12 octets.
 */
ATF_TC_WITHOUT_HEAD(tlv_dm);
ATF_TC_BODY(tlv_dm, tc)
{
	struct stamp_refl_conf	  c = { .stateful = true, .port = 862 };
	struct stamp_sender_conf  sc = { .dm = true, .ssid = 4 };
	struct sockaddr_in	  a = sin4("192.0.2.1", 40000);
	struct stamp_refl	 *r;
	struct stamp_sender	 *s;
	struct stamp_sender_stats st;
	struct stamp_sample	  sm;
	struct stamp_dm		  dm;
	struct stamp_tlv	  v;
	struct stamp_rx		  rx;
	struct timespec		  t1;
	enum stamp_drop		  why;
	uint8_t			  p[8][64], out[8][STAMP_PKT_MAX];
	size_t			  off;
	int			  i;

	ATF_REQUIRE((s = stamp_sender_new(&sc)) != NULL);
	ATF_CHECK_EQ(stamp_sender_len(s, 0), 60);
	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	clock_gettime(CLOCK_REALTIME, &t1);
	memset(&rx, 0, sizeof(rx));
	rx.len = 60;
	rx.peer = (struct sockaddr *)&a;
	rx.t2 = t1;
	/* Eight packets: the 2nd lost going, the 4th's reply lost coming,
	 * the 6th's and 7th's replies swapped. */
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE(stamp_sender_packet(s, p[i], 60, &t1, 1 + i * 0.1,
		    NULL) == 0);
		off = 0;
		ATF_REQUIRE(stamp_tlv_next(p[i], 60, &off, &v) == 1);
		ATF_CHECK(v.type == STAMP_TLV_DM && v.len == 12);
		ATF_CHECK(v.value[3] == i + 1 && v.value[7] == 0 &&
		    v.value[11] == 0);
		if (i == 1)
			continue;
		rx.pkt = p[i];
		rx.mono = 1 + i * 0.1;
		ATF_REQUIRE(stamp_refl_reply(r, &rx, out[i], sizeof(out[i]),
		    NULL) == 60);
	}
	ATF_REQUIRE(stamp_dm_find(out[0], 60, &dm) == 1);
	ATF_CHECK(dm.s_tx == 1 && dm.r_rx == 1 && dm.r_tx == 1);
	ATF_REQUIRE(stamp_dm_find(out[7], 60, &dm) == 1);
	ATF_CHECK(dm.s_tx == 8 && dm.r_rx == 7 && dm.r_tx == 7);
	for (i = 0; i < 8; i++) {
		if (i == 1 || i == 3)
			continue;
		ATF_REQUIRE(stamp_sender_reply(s, out[i == 5 ? 6 : i == 6 ? 5 :
		    i], 60, 1.05 + i * 0.1, NULL, &sm) == 1);
		ATF_CHECK(sm.has_dm);
	}
	stamp_sender_stats(s, &st);
	ATF_CHECK(st.dm_told);
	ATF_CHECK_EQ(st.dm_fwd_lost, 1);
	ATF_CHECK_EQ(st.dm_back_lost, 1);
	ATF_CHECK_EQ(sm.s_rx, 6);

	/* Over the rate: received, not sent; a stateless reflector's 0,
	 * none found. */
	c.rate = 1;
	c.burst = 1;
	ATF_REQUIRE(stamp_refl_setconf(r, &c) == 0);
	rx.pkt = p[7];
	rx.mono = 10;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out[0], sizeof(out[0]), NULL) ==
	    60);
	ATF_CHECK(stamp_refl_reply(r, &rx, out[1], sizeof(out[1]), &why) ==
	    -1 && why == STAMP_DROP_RATE);
	rx.mono = 12;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out[1], sizeof(out[1]), NULL) ==
	    60);
	ATF_REQUIRE(stamp_dm_find(out[1], 60, &dm) == 1);
	ATF_CHECK_EQ(dm.r_rx, 10);
	ATF_CHECK_EQ(dm.r_tx, 9);
	c.stateful = false;
	c.rate = 0;
	ATF_REQUIRE(stamp_refl_setconf(r, &c) == 0);
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out[0], sizeof(out[0]), NULL) ==
	    60);
	ATF_CHECK(stamp_dm_find(out[0], 60, &dm) == 0);
	ATF_CHECK(dm.s_tx == 8 && dm.r_rx == 0 && dm.r_tx == 0);
	/* Not 12 octets: malformed. */
	memcpy(p[0], p[7], 60);
	p[0][47] = 8;
	off = 44 + 4 + 8;
	ATF_REQUIRE(stamp_tlv_put(p[0], 60, &off, STAMP_TLV_PAD, NULL, 0) == 0);
	rx.pkt = p[0];
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out[0], sizeof(out[0]), NULL) ==
	    60);
	ATF_CHECK(out[0][44] == STAMP_TLV_M);
	ATF_CHECK(stamp_dm_find(out[0], 60, &dm) == 0);
	stamp_refl_free(r);
	stamp_sender_free(s);
}

/*
 * The Location TLV (RFC 8972 4.2): the ports and the source and
 * destination addresses the request came with, in its family; a NAT
 * on the way told; hidden by the configuration; a source MAC an EUI-64
 * of zero, an unknown sub-TLV marked, sub-TLVs past it malformed.
 */
ATF_TC_WITHOUT_HEAD(tlv_location);
ATF_TC_BODY(tlv_location, tc)
{
	struct stamp_refl_conf	 c = { .stateful = false, .port = 862 };
	struct stamp_sender_conf sc = { .location = true, .tsinfo = true };
	struct sockaddr_in	 a = sin4("192.0.2.1", 40000);
	struct sockaddr_in	 l = sin4("198.51.100.7", 0);
	struct sockaddr_in	 self = sin4("10.0.0.1", 40000);
	struct sockaddr_in	 far = sin4("198.51.100.7", 862);
	struct sockaddr_in6	 a6 = sin6("2001:db8::1", 40001);
	struct sockaddr_in6	 l6 = sin6("2001:db8::2", 0);
	struct sockaddr_in6	 far6 = sin6("2001:db8::2", 862);
	struct stamp_refl	*r;
	struct stamp_sender	*s;
	struct stamp_sample	 sm;
	struct stamp_location	 loc;
	struct stamp_tlv	 v;
	struct stamp_rx		 rx;
	struct timespec		 t1;
	uint8_t			 p[128], out[STAMP_PKT_MAX];
	size_t			 off;

	ATF_REQUIRE((s = stamp_sender_new(&sc)) != NULL);
	ATF_CHECK_EQ(stamp_sender_len(s, 0), 100);
	clock_gettime(CLOCK_REALTIME, &t1);
	ATF_REQUIRE(stamp_sender_packet(s, p, 100, &t1, 1, NULL) == 0);
	off = 52;
	ATF_REQUIRE(stamp_tlv_next(p, 100, &off, &v) == 1);
	ATF_CHECK(v.type == STAMP_TLV_LOCATION && v.len == 44);
	ATF_CHECK(v.value[0] == 0 && v.value[3] == 0);
	ATF_CHECK(v.value[5] == STAMP_SUB_DSTIP && v.value[7] == 16);
	ATF_CHECK(v.value[25] == STAMP_SUB_SRCIP && v.value[27] == 16);
	/* Asked, not answered: none said. */
	ATF_CHECK(stamp_location_find(p, 100, &loc) == 1);
	ATF_CHECK(loc.src.ss_family == 0 && loc.dst.ss_family == 0);

	/* IPv4: what it came from and to. */
	ATF_REQUIRE((r = stamp_refl_new(&c)) != NULL);
	memset(&rx, 0, sizeof(rx));
	rx.pkt = p;
	rx.len = 100;
	rx.peer = (struct sockaddr *)&a;
	rx.local = (struct sockaddr *)&l;
	rx.t2 = t1;
	rx.mono = 1;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	off = 52;
	ATF_REQUIRE(stamp_tlv_next(out, 100, &off, &v) == 1);
	ATF_CHECK(v.value[0] == 862 >> 8 && v.value[1] == (862 & 0xff));
	ATF_CHECK(v.value[2] == 40000 >> 8 && v.value[3] == (40000 & 0xff));
	ATF_CHECK(v.value[5] == STAMP_SUB_DSTIP4 && v.value[25] ==
	    STAMP_SUB_SRCIP4);
	ATF_CHECK(v.value[8] == 198 && v.value[11] == 7 && v.value[12] == 0);
	ATF_CHECK(v.value[28] == 192 && v.value[31] == 1);
	ATF_REQUIRE(stamp_sender_reply(s, out, 100, 1.01, NULL, &sm) == 1);
	ATF_REQUIRE(sm.has_loc);
	ATF_CHECK_EQ(sm.loc.src.ss_family, AF_INET);
	ATF_CHECK_EQ(stamp_sa_port((struct sockaddr *)&sm.loc.src), 40000);
	ATF_CHECK_EQ(stamp_sa_port((struct sockaddr *)&sm.loc.dst), 862);
	/* From 10.0.0.1, seen from 192.0.2.1: the source rewritten; to
	 * the address it reached, nothing else. */
	ATF_CHECK_EQ(stamp_location_nat(&sm.loc, (struct sockaddr *)&self,
	    (struct sockaddr *)&far), STAMP_NAT_SRC);
	ATF_CHECK_EQ(stamp_location_nat(&sm.loc, (struct sockaddr *)&a,
	    (struct sockaddr *)&far), 0);
	self = a;
	self.sin_port = htons(40002);
	ATF_CHECK_EQ(stamp_location_nat(&sm.loc, (struct sockaddr *)&self,
	    (struct sockaddr *)&far), STAMP_NAT_SRC);
	self.sin_port = 0;
	ATF_CHECK_EQ(stamp_location_nat(&sm.loc, (struct sockaddr *)&self,
	    NULL), 0);
	far.sin_port = htons(10862);
	ATF_CHECK_EQ(stamp_location_nat(&sm.loc, NULL,
	    (struct sockaddr *)&far), STAMP_NAT_DST);

	/* IPv6; the address it came to not known: that one not said. */
	rx.peer = (struct sockaddr *)&a6;
	rx.local = NULL;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	ATF_REQUIRE(stamp_location_find(out, 100, &loc) == 1);
	ATF_CHECK_EQ(loc.src.ss_family, AF_INET6);
	ATF_CHECK(memcmp(&((struct sockaddr_in6 *)&loc.src)->sin6_addr,
	    &a6.sin6_addr, 16) == 0);
	ATF_CHECK_EQ(stamp_sa_port((struct sockaddr *)&loc.src), 40001);
	ATF_CHECK_EQ(loc.dst.ss_family, 0);
	rx.local = (struct sockaddr *)&l6;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	ATF_REQUIRE(stamp_location_find(out, 100, &loc) == 1);
	ATF_CHECK_EQ(stamp_location_nat(&loc, (struct sockaddr *)&a6,
	    (struct sockaddr *)&far6), 0);
	off = 52;
	ATF_REQUIRE(stamp_tlv_next(out, 100, &off, &v) == 1);
	ATF_CHECK(v.value[5] == STAMP_SUB_DSTIP6 && v.value[25] ==
	    STAMP_SUB_SRCIP6);

	/* Hidden: nothing said. */
	c.loc_hide = true;
	ATF_REQUIRE(stamp_refl_setconf(r, &c) == 0);
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	ATF_REQUIRE(stamp_location_find(out, 100, &loc) == 1);
	ATF_CHECK(loc.src.ss_family == 0 && loc.dst.ss_family == 0);
	ATF_CHECK(out[56] == 0 && out[57] == 0 && out[58] == 0 &&
	    out[59] == 0);
	c.loc_hide = false;
	ATF_REQUIRE(stamp_refl_setconf(r, &c) == 0);

	/* A source MAC asked: an EUI-64 of zero; an unknown sub-TLV
	 * marked; its source address still said. */
	p[56 + 5] = STAMP_SUB_SRCMAC;
	p[56 + 7] = 8;
	p[56 + 16] = 0;		/* an 8-octet sub-TLV of type 99 after it */
	p[56 + 17] = 99;
	p[56 + 18] = 0;
	p[56 + 19] = 4;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	ATF_CHECK(out[56 + 5] == STAMP_SUB_EUI64);
	ATF_CHECK(out[56 + 16] == STAMP_TLV_U && out[56 + 17] == 99);
	ATF_CHECK(out[56 + 25] == STAMP_SUB_SRCIP6);
	ATF_REQUIRE(stamp_location_find(out, 100, &loc) == 1);
	ATF_CHECK(loc.src.ss_family == AF_INET6 && loc.dst.ss_family == 0);
	/* Sub-TLVs past it: malformed, none found. */
	p[56 + 27] = 30;
	ATF_REQUIRE(stamp_refl_reply(r, &rx, out, sizeof(out), NULL) == 100);
	ATF_CHECK(out[52] == STAMP_TLV_M);
	ATF_CHECK(stamp_location_find(out, 100, &loc) == 0);
	stamp_refl_free(r);
	stamp_sender_free(s);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, tlv_cos);
	ATF_TP_ADD_TC(tp, tlv_dm);
	ATF_TP_ADD_TC(tp, tlv_location);
	ATF_TP_ADD_TC(tp, clock_set);
	ATF_TP_ADD_TC(tp, tlv_tsinfo);
	ATF_TP_ADD_TC(tp, sender_owd);
	ATF_TP_ADD_TC(tp, sender_owd_bounds);

	ATF_TP_ADD_TC(tp, sender_rtt);
	ATF_TP_ADD_TC(tp, sender_loss_stateful);
	ATF_TP_ADD_TC(tp, sender_loss_stateless);
	ATF_TP_ADD_TC(tp, sender_window);
	ATF_TP_ADD_TC(tp, sender_restart);

	ATF_TP_ADD_TC(tp, ntp_roundtrip);
	ATF_TP_ADD_TC(tp, error_estimate);
	ATF_TP_ADD_TC(tp, test_packet);
	ATF_TP_ADD_TC(tp, tlv);
	ATF_TP_ADD_TC(tp, reflect_fields);
	ATF_TP_ADD_TC(tp, reflect_short);
	ATF_TP_ADD_TC(tp, reflect_port);
	ATF_TP_ADD_TC(tp, reflect_stateful);
	ATF_TP_ADD_TC(tp, reflect_sessions_max);
	ATF_TP_ADD_TC(tp, reflect_rate);
	return (atf_no_error());
}
