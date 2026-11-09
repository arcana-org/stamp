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

ATF_TP_ADD_TCS(tp)
{

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
