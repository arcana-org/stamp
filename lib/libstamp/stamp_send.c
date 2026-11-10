/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Session-Sender's core (RFC 8762 4.2), unauthenticated, with the
 * Session-Sender Identifier of RFC 8972 3.  No socket here, as in the
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
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
	struct stamp_sender_stats st;
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

/*
 * The length of a packet of the sender's for one of want octets: the
 * base's at least, and with the Timestamp Information TLV, its too,
 * what is left after it 0 or an Extra Padding TLV's 4 octets or more.
 */
size_t
stamp_sender_len(const struct stamp_sender *s, size_t want)
{
	size_t	min = STAMP_UNAUTH_LEN;

	if (s->c.tsinfo)
		min += STAMP_TSINFO_LEN;
	if (want < min)
		return (min);
	if (s->c.tsinfo && want - min > 0 && want - min < STAMP_TLV_HDR)
		return (min + STAMP_TLV_HDR);
	return (want);
}

/*
 * The next test packet into buf (len octets, STAMP_UNAUTH_LEN or more;
 * what follows the base left as it is, or with tsinfo the Timestamp
 * Information TLV, empty, and an Extra Padding TLV over the rest, its
 * octets left as they are: len as stamp_sender_len() says), sent at t1
 * (the time of day, in the packet) and mono (monotonic seconds).  0; 1
 * when the window was full and its oldest packet given up, lost, its
 * sample in *lostp; -1 with errno.
 */
int
stamp_sender_packet(struct stamp_sender *s, uint8_t *buf, size_t len,
    const struct timespec *t1, double mono, struct stamp_sample *lostp)
{
	static const uint8_t	 empty[4];
	struct stamp_test	 t;
	struct ent		*e;
	size_t			 off;
	int			 rc = 0;

	if (len < STAMP_UNAUTH_LEN || stamp_sender_len(s, len) != len) {
		errno = EMSGSIZE;
		return (-1);
	}
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
	if (s->c.tsinfo) {
		off = STAMP_UNAUTH_LEN;
		if (stamp_tlv_put(buf, len, &off, STAMP_TLV_TSINFO, empty,
		    sizeof(empty)) == -1)
			return (-1);
		if (len > off && stamp_tlv_put(buf, len, &off, STAMP_TLV_PAD,
		    NULL, (uint16_t)(len - off - STAMP_TLV_HDR)) == -1)
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
 * A reply (len octets) that came at mono, and t4 (the time of day; NULL
 * not known): 1 and its sample in *out when it answers a packet in
 * flight; 0 when it is none (another session's, late, again); -1 when
 * it is no reflected packet (errno).
 */
int
stamp_sender_reply(struct stamp_sender *s, const uint8_t *pkt, size_t len,
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
	}
	advance(s);
	return (1);
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
}
