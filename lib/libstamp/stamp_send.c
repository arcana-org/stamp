/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Session-Sender's core (RFC 8762 4.2), with the Session-Sender
 * Identifier of RFC 8972 3, in either mode.  No socket here, as in the
 * reflector's: the caller sends the packet it is given and hands over
 * each reply as it came, with the monotonic time of each; out come a
 * sample a packet, its round trip or its loss, and the counts.
 *
 * The round trip has the reflector's time taken out: (T4 - T1) -
 * (T3 - T2), T1 and T4 on this host's monotonic clock (a step of the
 * time of day changes nothing), T2 and T3 both the reflector's, so
 * that neither clock need be right.
 *
 * The delay each way does need them right: (T2 - T1) forward and
 * (T4 - T3) back, T1 and T4 on the time of day, said only when both
 * ends' Error Estimates say their clocks are synchronised (S) and the
 * two errors together are no more than owd_frac (a tenth) of half the
 * round trip, so that what is said is right to a tenth; otherwise half
 * the round trip each way, flagged an estimate.  With tsinfo the
 * packets carry the Timestamp Information TLV (RFC 8972 4.3), which
 * the reflector fills: its clock's source, how it took T2 and T3.
 * With cos, the Class of Service TLV (4.4) asks the reflector to send
 * its reply with the DSCP dscp (the caller sends its packets with the
 * DSCP it wants, on its socket) and tells the DSCP and ECN the packet
 * reached the reflector with; the DSCP the reply came back with is the
 * caller's to read (stamp_recv()).  With location, the Location TLV
 * (4.2) asks for the addresses and ports the packet reached the
 * reflector with: a NAT on the way rewrote them (stamp_location_nat()).
 *
 * With dm, the Direct Measurement TLV (4.5) carries the packets sent in
 * the session, this one with them, and comes back with what the
 * reflector received and sent in it, a stateful reflector counting:
 * the loss each way by counters too.  Between two replies that have
 * them, the packets sent less those the reflector received were lost
 * on the way out, the replies it sent less those received here on the
 * way back; summed from the first such reply (dm_told).  A reply that
 * comes before one sent earlier (reordered) is passed over; counters
 * that go back (the reflector started again) start the sum's next
 * part from that reply.
 *
 * A packet not back within the timeout is lost.  Which way it was lost
 * a stateful reflector tells (4.3.2): its Sequence Number counts the
 * packets of the session it reflected, so between two replies the
 * sender's numbers say how many were sent and the reflector's how many
 * reached it; those that did not were lost on the way out, the others
 * on the way back (a reply after its timeout among them).  A stateless
 * reflector copies the sender's number: its losses are the round
 * trip's alone, said apart (unknown_lost).  Which kind of reflector it
 * is the first reply tells, the first number being random and not 0
 * (a stateful reflector's new session starts at 0); one that later
 * gives its own numbers is stateful from then on.  A counter that goes
 * back or leaps (the reflector started again) leaves that gap unknown.
 *
 * The packets in flight are a ring, as many as the window; one more
 * sent gives up the oldest, lost.  The losses between two replies are
 * told apart when the later one is passed, every packet before it
 * answered or lost: the counts trail the samples by up to the timeout.
 *
 * With a key, the packets are of the authenticated mode (RFC 8762
 * 4.2.2): 112 octets of base, its HMAC over the first 96, and the TLVs
 * after it followed by RFC 8972's HMAC TLV (4.8) over them, the Extra
 * Padding after that.  A reply is taken only when it is of that layout
 * and its HMAC verifies under the key (auth_failed otherwise: a reply
 * tampered with, or a reflector of another key, is no reply, and its
 * packet is lost when its time comes); its TLVs only when they are
 * well-formed to its end, its HMAC TLV verifies and the reflector
 * flagged none I (tlv_failed): otherwise the base alone is used.
 * Authenticated, what follows the base is always TLVs: the padding an
 * Extra Padding TLV, with or without other TLVs.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "stamp.h"

#define	SND_TIMEOUT	2.0
#define	SND_WINDOW	256
#define	SND_WINDOW_MAX	65536

enum { E_FREE = 0, E_PENDING, E_REPLIED, E_LOST };

struct ent {
	uint8_t		 st;
	double		 mono;		/* sent */
	struct timespec	 t1;		/* the same, the time of day */
	uint16_t	 ee;		/* the Error Estimate it carried */
	uint32_t	 rseq;		/* the reflector's, replied */
};

struct stamp_sender {
	struct stamp_sender_conf  c;
	struct ent		 *ring;
	uint32_t		  mask;
	uint32_t		  head;		/* the oldest not yet passed */
	uint32_t		  next;		/* the next sent */
	uint32_t		  a_rseq;	/* the last reply passed's */
	bool			  anchored;
	uint64_t		  gap;		/* lost since that reply */
	uint16_t		  ee;
	double			  ee_at;
	/* The Direct Measurement counters of the last reply that had
	 * them, and the losses each way they told since the first. */
	bool			  dm_have;
	uint32_t		  p_stx, p_rrx, p_rtx, p_srx;
	int64_t			  dm_fwd, dm_back;
	struct stamp_sender_stats st;
	/* The authenticated mode: the key, a reply narrowed. */
	bool			  auth;
	struct stamp_key	  key;
	uint8_t			 *view;		/* STAMP_PKT_MAX */
};

const char *
stamp_mode_name(enum stamp_mode m)
{

	return (m == STAMP_MODE_STATELESS ? "stateless" : m ==
	    STAMP_MODE_STATEFUL ? "stateful" : "unknown");
}

struct stamp_sender *
stamp_sender_new(const struct stamp_sender_conf *c)
{
	struct stamp_sender	*s;
	uint32_t		 cap;

	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (NULL);
	s->c = *c;
	if (c->key != NULL) {
		if (c->key->len < 1 || c->key->len > STAMP_KEY_MAX ||
		    (s->view = malloc(STAMP_PKT_MAX)) == NULL) {
			if (c->key->len < 1 || c->key->len > STAMP_KEY_MAX)
				errno = EINVAL;
			free(s);
			return (NULL);
		}
		s->key = *c->key;
		s->auth = true;
	}
	s->c.key = NULL;
	if (s->c.timeout <= 0)
		s->c.timeout = SND_TIMEOUT;
	if (s->c.window == 0)
		s->c.window = SND_WINDOW;
	if (s->c.window > SND_WINDOW_MAX)
		s->c.window = SND_WINDOW_MAX;
	if (s->c.owd_frac <= 0)
		s->c.owd_frac = STAMP_OWD_FRAC;
	for (cap = 1; cap < s->c.window; cap <<= 1)
		;
	if ((s->ring = calloc(cap, sizeof(*s->ring))) == NULL) {
		explicit_bzero(&s->key, sizeof(s->key));
		free(s->view);
		free(s);
		return (NULL);
	}
	s->mask = cap - 1;
	if (!s->c.seq_set)
		while ((s->c.seq0 = arc4random()) == 0)
			;
	s->head = s->next = s->c.seq0;
	s->st.mode = s->c.mode;
	return (s);
}

void
stamp_sender_free(struct stamp_sender *s)
{

	if (s == NULL)
		return;
	explicit_bzero(&s->key, sizeof(s->key));
	free(s->view);
	free(s->ring);
	free(s);
}

/* The losses since the last reply passed, told apart by the reflector's
 * number of the one passed now. */
static void
attribute(struct stamp_sender *s, uint32_t rseq)
{
	uint32_t	d;

	if (s->anchored && s->st.mode == STAMP_MODE_STATEFUL) {
		/* Reflected since the last reply: this one and d - 1 more. */
		d = rseq - s->a_rseq;
		if (d >= 1 && d - 1 <= s->gap) {
			s->st.back_lost += d - 1;
			s->st.fwd_lost += s->gap - (d - 1);
		} else
			s->st.unknown_lost += s->gap;
	} else
		s->st.unknown_lost += s->gap;
	s->gap = 0;
}

/* Past the packets answered or lost, the oldest first. */
static void
advance(struct stamp_sender *s)
{
	struct ent	*e;

	while (s->head != s->next) {
		e = &s->ring[s->head & s->mask];
		if (e->st == E_PENDING)
			break;
		if (e->st == E_LOST)
			s->gap++;
		else {
			if (s->gap > 0)
				attribute(s, e->rseq);
			s->a_rseq = e->rseq;
			s->anchored = true;
		}
		e->st = E_FREE;
		s->head++;
	}
}

static void
lose(struct stamp_sender *s, uint32_t seq, struct stamp_sample *out)
{

	s->ring[seq & s->mask].st = E_LOST;
	s->st.lost++;
	if (out != NULL) {
		memset(out, 0, sizeof(*out));
		out->seq = seq;
		out->lost = true;
	}
	advance(s);
}

/* The octets of the TLVs the sender's packets carry, Extra Padding's
 * aside: authenticated, the HMAC TLV after them. */
static size_t
tlvs_len(const struct stamp_sender *s)
{
	size_t	n;

	n = (s->c.tsinfo ? STAMP_TSINFO_LEN : 0) + (s->c.cos ?
	    STAMP_COS_LEN : 0) + (s->c.dm ? STAMP_DM_LEN : 0) +
	    (s->c.location ? STAMP_LOCATION_LEN : 0);
	return (n > 0 && s->auth ? n + STAMP_HMAC_TLV_LEN : n);
}

/* The base packet's octets: 44, or authenticated 112. */
static size_t
base_len(const struct stamp_sender *s)
{

	return (s->auth ? STAMP_AUTH_LEN : STAMP_UNAUTH_LEN);
}

/*
 * The length of a packet of the sender's for one of want octets: the
 * base's at least (112 authenticated), and with TLVs (Timestamp
 * Information, Class of Service, Direct Measurement, Location; the HMAC
 * TLV authenticated), theirs too, what is left after them 0 or an Extra
 * Padding TLV's 4 octets or more (always a TLV authenticated, with TLVs
 * or without: nothing but TLVs may follow an authenticated base).
 */
size_t
stamp_sender_len(const struct stamp_sender *s, size_t want)
{
	size_t	min = base_len(s) + tlvs_len(s);

	if (want < min)
		return (min);
	if ((tlvs_len(s) > 0 || s->auth) && want - min > 0 && want - min <
	    STAMP_TLV_HDR)
		return (min + STAMP_TLV_HDR);
	return (want);
}

/*
 * The next test packet into buf (len octets, STAMP_UNAUTH_LEN or more;
 * what follows the base left as it is, or with TLVs asked for, they,
 * in that order, empty but for the Class of Service TLV's DSCP1, the
 * Direct Measurement TLV's S_TxC and the Location TLV's sub-TLVs
 * asking for the destination and source addresses, and an Extra Padding
 * TLV over the rest, its octets left as they are: len as
 * stamp_sender_len() says), sent at t1 (the time of day, in the packet)
 * and mono (monotonic seconds).  0; 1 when the window was full and its
 * oldest packet given up, lost, its sample in *lostp; -1 with errno.
 */
int
stamp_sender_packet(struct stamp_sender *s, uint8_t *buf, size_t len,
    const struct timespec *t1, double mono, struct stamp_sample *lostp)
{
	static const uint8_t	 empty[4];
	uint8_t			 cos[4], dm[12], loc[44];
	uint32_t		 stx;
	struct stamp_test	 t;
	struct ent		*e;
	size_t			 off, wide;
	int			 rc = 0;

	if (len < base_len(s) || stamp_sender_len(s, len) != len) {
		errno = EMSGSIZE;
		return (-1);
	}
	/* Authenticated: made narrow, widened after. */
	wide = s->auth ? STAMP_AUTH_LEN - STAMP_UNAUTH_LEN : 0;
	len -= wide;
	if (s->next - s->head >= s->c.window) {
		lose(s, s->head, lostp);
		rc = 1;
	}
	/* The Error Estimate, the clock's, looked at once a second. */
	if (s->ee == 0 || mono - s->ee_at >= 1) {
		s->ee = stamp_ee_clock();
		s->ee_at = mono;
	}
	memset(&t, 0, sizeof(t));
	t.seq = s->next;
	t.ts = *t1;
	t.ee = s->ee;
	t.ssid = s->c.ssid;
	if (stamp_test_encode(buf, len, &t) == -1)
		return (-1);
	off = STAMP_UNAUTH_LEN;
	if (s->c.tsinfo && stamp_tlv_put(buf, len, &off, STAMP_TLV_TSINFO,
	    empty, sizeof(empty)) == -1)
		return (-1);
	if (s->c.cos) {
		memset(cos, 0, sizeof(cos));
		cos[0] = (uint8_t)((s->c.dscp & 0x3f) << 2);
		if (stamp_tlv_put(buf, len, &off, STAMP_TLV_COS, cos,
		    sizeof(cos)) == -1)
			return (-1);
	}
	if (s->c.dm) {
		/* Sent in the session, this one too. */
		memset(dm, 0, sizeof(dm));
		stx = (uint32_t)(s->st.sent + 1);
		dm[0] = (uint8_t)(stx >> 24);
		dm[1] = (uint8_t)(stx >> 16);
		dm[2] = (uint8_t)(stx >> 8);
		dm[3] = (uint8_t)stx;
		if (stamp_tlv_put(buf, len, &off, STAMP_TLV_DM, dm,
		    sizeof(dm)) == -1)
			return (-1);
	}
	if (s->c.location) {
		/* The ports, then the destination and the source asked,
		 * each sub-TLV's U set as a TLV's (RFC 8972 4.2). */
		memset(loc, 0, sizeof(loc));
		loc[4] = STAMP_TLV_U;
		loc[5] = STAMP_SUB_DSTIP;
		loc[7] = 16;
		loc[24] = STAMP_TLV_U;
		loc[25] = STAMP_SUB_SRCIP;
		loc[27] = 16;
		if (stamp_tlv_put(buf, len, &off, STAMP_TLV_LOCATION, loc,
		    sizeof(loc)) == -1)
			return (-1);
	}
	/* The HMAC TLV after them, made once the packet is wide. */
	if (s->auth && tlvs_len(s) > 0 && stamp_tlv_put(buf, len, &off,
	    STAMP_TLV_HMAC, NULL, STAMP_HMAC_LEN) == -1)
		return (-1);
	if ((tlvs_len(s) > 0 || s->auth) && len > off && stamp_tlv_put(buf, len,
	    &off, STAMP_TLV_PAD, NULL, (uint16_t)(len - off - STAMP_TLV_HDR)) ==
	    -1)
		return (-1);
	if (s->auth) {
		stamp_auth_widen(buf, len, false);
		len += wide;
		if (stamp_auth_tlv_seal(&s->key, buf, len, STAMP_AUTH_LEN) == -1
		    || stamp_auth_seal(&s->key, buf, len) == -1)
			return (-1);
	}
	e = &s->ring[s->next & s->mask];
	e->st = E_PENDING;
	e->mono = mono;
	e->t1 = *t1;
	e->ee = s->ee;
	e->rseq = 0;
	s->next++;
	s->st.sent++;
	return (rc);
}

/*
 * The delay each way of a reply's sample: one way when both ends'
 * Error Estimates say synchronised and their errors together are
 * within owd_frac of half the round trip, neither way negative; else
 * half the round trip each, an estimate.  t4 NULL: not known.
 */
static void
one_way(const struct stamp_sender *s, const struct ent *e,
    const struct stamp_reflected *r, const struct timespec *t4,
    struct stamp_sample *out)
{
	double	fwd, back;

	out->err = stamp_ee_seconds(e->ee) + stamp_ee_seconds(r->ee);
	out->owd = false;
	if (t4 != NULL && (e->ee & STAMP_EE_S) && (r->ee & STAMP_EE_S) &&
	    out->err <= s->c.owd_frac * out->rtt / 2) {
		fwd = stamp_ts_sub(&r->rx, &e->t1);
		back = stamp_ts_sub(t4, &r->ts);
		if (fwd >= 0 && back >= 0) {
			out->fwd = fwd;
			out->back = back;
			out->owd = true;
			return;
		}
	}
	out->fwd = out->back = out->rtt / 2;
}

/*
 * A reply's Direct Measurement counters: the losses each way since the
 * last that had them, summed.
 */
static void
dm_count(struct stamp_sender *s, const struct stamp_dm *dm, uint32_t srx)
{
	uint32_t	dstx, drrx, drtx, dsrx;

	if (s->dm_have) {
		dstx = dm->s_tx - s->p_stx;
		drrx = dm->r_rx - s->p_rrx;
		drtx = dm->r_tx - s->p_rtx;
		dsrx = srx - s->p_srx;
		/* Before the last one: reordered, passed over. */
		if ((int32_t)dstx < 0)
			return;
		/* Counters gone back: from this one again. */
		if ((int32_t)drrx >= 0 && (int32_t)drtx >= 0) {
			s->dm_fwd += (int64_t)dstx - (int64_t)drrx;
			s->dm_back += (int64_t)drtx - (int64_t)dsrx;
		}
	}
	s->dm_have = true;
	s->p_stx = dm->s_tx;
	s->p_rrx = dm->r_rx;
	s->p_rtx = dm->r_tx;
	s->p_srx = srx;
}

/* A reply of the unauthenticated layout, as stamp_sender_reply(). */
static int
reply_core(struct stamp_sender *s, const uint8_t *pkt, size_t len,
    double mono, const struct timespec *t4, struct stamp_sample *out)
{
	struct stamp_reflected	 r;
	struct ent		*e;
	double			 raw, refl;

	if (stamp_reflected_decode(pkt, len, &r) == -1)
		return (-1);
	if (r.ssid != s->c.ssid) {
		s->st.foreign++;
		return (0);
	}
	if ((uint32_t)(r.sseq - s->head) >= (uint32_t)(s->next - s->head)) {
		/* Before the window: answered or lost already. */
		if ((uint32_t)(s->head - r.sseq) <= s->c.window * 4U)
			s->st.late++;
		else
			s->st.foreign++;
		return (0);
	}
	e = &s->ring[r.sseq & s->mask];
	if (e->st != E_PENDING) {
		s->st.late++;
		return (0);
	}
	raw = mono - e->mono;
	refl = stamp_ts_sub(&r.ts, &r.rx);
	/* Clocks that disagree with what was seen: what can be said. */
	if (refl < 0)
		refl = 0;
	if (refl > raw)
		refl = raw;
	if (s->st.mode == STAMP_MODE_UNKNOWN)
		s->st.mode = r.seq == r.sseq ? STAMP_MODE_STATELESS :
		    STAMP_MODE_STATEFUL;
	else if (s->st.mode == STAMP_MODE_STATELESS && r.seq != r.sseq) {
		s->st.mode = STAMP_MODE_STATEFUL;
		s->anchored = false;
	}
	e->st = E_REPLIED;
	e->rseq = r.seq;
	s->st.received++;
	if (out != NULL) {
		memset(out, 0, sizeof(*out));
		out->seq = r.sseq;
		out->rtt = raw - refl;
		out->refl = refl;
		out->r = r;
		one_way(s, e, &r, t4, out);
		out->has_tsinfo = stamp_tsinfo_find(pkt, len, &out->tsinfo) ==
		    1;
		out->has_cos = stamp_cos_find(pkt, len, &out->cos) == 1;
		out->has_loc = stamp_location_find(pkt, len, &out->loc) == 1;
		out->s_rx = (uint32_t)s->st.received;
		if ((out->has_dm = stamp_dm_find(pkt, len, &out->dm) == 1))
			dm_count(s, &out->dm, out->s_rx);
	} else {
		struct stamp_dm	dm;

		if (stamp_dm_find(pkt, len, &dm) == 1)
			dm_count(s, &dm, (uint32_t)s->st.received);
	}
	advance(s);
	return (1);
}

/*
 * A reply (len octets) that came at mono, and t4 (the time of day; NULL
 * not known): 1 and its sample in *out when it answers a packet in
 * flight; 0 when it is none (another session's, late, again; with a
 * key, not of the authenticated layout or its HMAC wrong); -1 when it
 * is no reflected packet (errno).
 */
int
stamp_sender_reply(struct stamp_sender *s, const uint8_t *pkt, size_t len,
    double mono, const struct timespec *t4, struct stamp_sample *out)
{
	size_t	n;

	if (!s->auth)
		return (reply_core(s, pkt, len, mono, t4, out));
	if (len > STAMP_PKT_MAX || !stamp_auth_layout(pkt, len) ||
	    !stamp_auth_verify(&s->key, pkt, len)) {
		s->st.auth_failed++;
		return (0);
	}
	memcpy(s->view, pkt, len);
	stamp_auth_narrow(s->view, len, true);
	n = len - (STAMP_AUTH_LEN - STAMP_UNAUTH_LEN);
	/* Its TLVs not to be trusted: the base alone. */
	if (stamp_auth_tlv_verify(&s->key, pkt, len, STAMP_AUTH_LEN) != 1) {
		s->st.tlv_failed++;
		n = STAMP_UNAUTH_LEN;
	} else {
		struct stamp_tlv	v;
		size_t			off = STAMP_UNAUTH_LEN;

		while (stamp_tlv_next(s->view, n, &off, &v) == 1)
			if (v.type != 0 && (v.flags & STAMP_TLV_I)) {
				s->st.tlv_failed++;
				n = STAMP_UNAUTH_LEN;
				break;
			}
	}
	return (reply_core(s, s->view, n, mono, t4, out));
}

/* The oldest packet in flight past its timeout at mono, lost: 1 and
 * its sample in *out; 0 when there is none.  Called until 0. */
int
stamp_sender_expire(struct stamp_sender *s, double mono,
    struct stamp_sample *out)
{
	uint32_t	q;

	for (q = s->head; q != s->next; q++) {
		if (s->ring[q & s->mask].st != E_PENDING)
			continue;
		if (mono - s->ring[q & s->mask].mono < s->c.timeout)
			return (0);
		lose(s, q, out);
		return (1);
	}
	return (0);
}

/* When the oldest packet in flight times out (monotonic seconds); 0
 * with none in flight. */
double
stamp_sender_next(const struct stamp_sender *s)
{
	uint32_t	q;

	for (q = s->head; q != s->next; q++)
		if (s->ring[q & s->mask].st == E_PENDING)
			return (s->ring[q & s->mask].mono + s->c.timeout);
	return (0);
}

void
stamp_sender_stats(const struct stamp_sender *s, struct stamp_sender_stats *st)
{

	*st = s->st;
	st->dm_told = s->dm_have;
	st->dm_fwd_lost = s->dm_fwd > 0 ? (uint64_t)s->dm_fwd : 0;
	st->dm_back_lost = s->dm_back > 0 ? (uint64_t)s->dm_back : 0;
}
