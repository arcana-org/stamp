/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Session-Reflector's core (RFC 8762 4.3), unauthenticated, with
 * the Session-Sender Identifier of RFC 8972 3; it answers a TWAMP
 * Light Session-Sender (RFC 5357 Appendix I) that pads its packets to
 * 44 octets or more, the offsets being the same.  No socket here: a
 * packet as it came (struct stamp_rx) in, the reply out.
 *
 * Stateless, the reply's Sequence Number is the sender's; stateful, it
 * counts the packets reflected in the session (4.3.2), a session the
 * caller's tag (a FIB), the sender's address and port, the address the
 * packet came to and the SSID, so that the sender tells loss on the
 * way out from loss on the way back.  Sessions are bounded (sess_max,
 * the oldest replaced when full) and end after sess_idle seconds
 * without a packet.
 *
 * A reflector answers whoever writes a source address, so it is no
 * amplifier and no firehose.  Only a packet of STAMP_UNAUTH_LEN octets
 * or more is answered, the reply exactly as long, what follows the
 * base copied (padding, TLVs; the Timestamp Information TLV filled,
 * those not known marked so).  Not one from port 0 nor from the
 * reflector's own port (two reflectors made to answer each other
 * forever by one forged packet).  And no more replies to one source
 * address than its token bucket allows, nor to all of them together
 * than one more: the sources' buckets a table of RL_SLOTS, RL_WAYS a
 * set, its hash keyed by a random secret so that no sender chooses
 * whom it displaces, a new source taking the set's oldest.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "stamp.h"

#define	SESS_BUCKETS	1024
#define	RL_SLOTS	4096
#define	RL_WAYS		4

struct sess {
	bool			 used;
	int			 tag;
	uint16_t		 ssid;
	struct sockaddr_storage	 peer;		/* address and port */
	struct sockaddr_storage	 local;		/* address only */
	uint32_t		 seq;		/* the next reflected */
	double			 last;
	int			 next;		/* in its bucket; -1 the end */
};

struct rl {
	uint8_t		 addr[16];	/* an IPv4 address mapped */
	double		 tokens;
	double		 last;		/* 0: unused */
};

struct stamp_refl {
	struct stamp_refl_conf	 c;
	struct sess		*sess;
	unsigned		 nsessmax;
	int			 bucket[SESS_BUCKETS];
	size_t			 nsess;
	struct rl		 rl[RL_SLOTS];
	uint32_t		 key;
	double			 all_tokens, all_last;
	struct stamp_clock	 clk;
	double			 clk_at;
	struct stamp_refl_stats	 st;
};

double
stamp_mono(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

/* ---- Sessions --------------------------------------------------- */

static bool
addr_eq(const struct sockaddr_storage *a, const struct sockaddr_storage *b,
    bool port)
{
	const struct sockaddr_in	*a4, *b4;
	const struct sockaddr_in6	*a6, *b6;

	if (a->ss_family != b->ss_family)
		return (false);
	if (a->ss_family == AF_INET) {
		a4 = (const struct sockaddr_in *)(const void *)a;
		b4 = (const struct sockaddr_in *)(const void *)b;
		return (a4->sin_addr.s_addr == b4->sin_addr.s_addr &&
		    (!port || a4->sin_port == b4->sin_port));
	}
	if (a->ss_family == AF_INET6) {
		a6 = (const struct sockaddr_in6 *)(const void *)a;
		b6 = (const struct sockaddr_in6 *)(const void *)b;
		return (memcmp(&a6->sin6_addr, &b6->sin6_addr, 16) == 0 &&
		    a6->sin6_scope_id == b6->sin6_scope_id &&
		    (!port || a6->sin6_port == b6->sin6_port));
	}
	return (true);
}

/* A sockaddr into storage, as long as its family says. */
static void
sa_copy(struct sockaddr_storage *ss, const struct sockaddr *sa)
{

	memset(ss, 0, sizeof(*ss));
	if (sa == NULL)
		return;
	if (sa->sa_family == AF_INET)
		memcpy(ss, sa, sizeof(struct sockaddr_in));
	else if (sa->sa_family == AF_INET6)
		memcpy(ss, sa, sizeof(struct sockaddr_in6));
	else
		ss->ss_family = sa->sa_family;
}

/* The address's 16 octets, an IPv4 one mapped, and its port. */
static void
addr16(const struct sockaddr *sa, uint8_t a[16], uint16_t *port)
{

	memset(a, 0, 16);
	*port = 0;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *s4 =
		    (const struct sockaddr_in *)(const void *)sa;

		a[10] = a[11] = 0xff;
		memcpy(a + 12, &s4->sin_addr, 4);
		*port = s4->sin_port;
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 =
		    (const struct sockaddr_in6 *)(const void *)sa;

		memcpy(a, &s6->sin6_addr, 16);
		*port = s6->sin6_port;
	}
}

/* FNV-1a over the session's key. */
static unsigned
sess_hash(int tag, uint16_t ssid, const struct sockaddr_storage *peer)
{
	uint8_t		a[16];
	uint16_t	port;
	uint32_t	h = 2166136261U;
	int		i;

	addr16((const struct sockaddr *)(const void *)peer, a, &port);
	for (i = 0; i < 16; i++)
		h = (h ^ a[i]) * 16777619U;
	h = (h ^ (port & 0xff)) * 16777619U;
	h = (h ^ (port >> 8)) * 16777619U;
	h = (h ^ (ssid & 0xff)) * 16777619U;
	h = (h ^ (ssid >> 8)) * 16777619U;
	h = (h ^ (uint32_t)tag) * 16777619U;
	return (h % SESS_BUCKETS);
}

static void
sess_unlink(struct stamp_refl *r, int i)
{
	struct sess	*s = &r->sess[i];
	int		*pp;

	for (pp = &r->bucket[sess_hash(s->tag, s->ssid, &s->peer)]; *pp != -1;
	    pp = &r->sess[*pp].next)
		if (*pp == i) {
			*pp = s->next;
			break;
		}
	s->used = false;
	r->nsess--;
}

void
stamp_refl_expire(struct stamp_refl *r, double now)
{
	unsigned	i;

	if (now == 0)
		now = stamp_mono();
	for (i = 0; r->sess != NULL && i < r->nsessmax && r->nsess > 0; i++)
		if (r->sess[i].used && now - r->sess[i].last >=
		    (double)r->c.sess_idle)
			sess_unlink(r, (int)i);
}

/* The session's next Sequence Number, the session made if new (the
 * oldest replaced when the table is full). */
static uint32_t
sess_seq(struct stamp_refl *r, int tag, uint16_t ssid,
    const struct sockaddr_storage *peer, const struct sockaddr_storage *local,
    double now)
{
	struct sess	*s;
	unsigned	 b;
	int		 i, free_i, old_i;

	b = sess_hash(tag, ssid, peer);
	for (i = r->bucket[b]; i != -1; i = r->sess[i].next) {
		s = &r->sess[i];
		if (s->tag == tag && s->ssid == ssid && addr_eq(&s->peer, peer,
		    true) && addr_eq(&s->local, local, false)) {
			s->last = now;
			return (s->seq++);
		}
	}
	free_i = old_i = -1;
	for (i = 0; i < (int)r->nsessmax; i++) {
		if (!r->sess[i].used) {
			free_i = i;
			break;
		}
		if (old_i == -1 || r->sess[i].last < r->sess[old_i].last)
			old_i = i;
	}
	if (free_i == -1) {
		sess_unlink(r, old_i);
		free_i = old_i;
	}
	s = &r->sess[free_i];
	memset(s, 0, sizeof(*s));
	s->used = true;
	s->tag = tag;
	s->ssid = ssid;
	s->peer = *peer;
	s->local = *local;
	s->last = now;
	s->seq = 1;
	s->next = r->bucket[b];
	r->bucket[b] = free_i;
	r->nsess++;
	return (0);
}

/* ---- Rate ------------------------------------------------------- */

/* A bucket of rate rt and burst b at t: a token taken if there is one. */
static bool
bucket_take(double *tokens, double *last, double rt, double b, double t)
{

	if (*last == 0)
		*tokens = b;
	else if ((*tokens += (t - *last) * rt) > b)
		*tokens = b;
	*last = t;
	if (*tokens < 1)
		return (false);
	*tokens -= 1;
	return (true);
}

static bool
rate_ok(struct stamp_refl *r, const struct sockaddr *peer, double t)
{
	struct rl	*b, *victim;
	uint8_t		 a[16];
	uint16_t	 port;
	uint32_t	 h;
	int		 i, set;

	if (r->c.rate > 0) {
		addr16(peer, a, &port);
		h = r->key;
		for (i = 0; i < 16; i++)
			h = (h ^ a[i]) * 16777619U;
		set = (int)(h % (RL_SLOTS / RL_WAYS)) * RL_WAYS;
		victim = NULL;
		for (i = 0; i < RL_WAYS; i++) {
			b = &r->rl[set + i];
			if (b->last != 0 && memcmp(b->addr, a, 16) == 0)
				break;
			if (victim == NULL || b->last < victim->last)
				victim = b;
		}
		if (i == RL_WAYS) {
			/* New: in the set's oldest, its bucket full. */
			b = victim;
			memcpy(b->addr, a, 16);
			b->last = 0;
		}
		if (!bucket_take(&b->tokens, &b->last, r->c.rate, r->c.burst,
		    t))
			return (false);
	}
	if (r->c.rate_total > 0 && !bucket_take(&r->all_tokens, &r->all_last,
	    r->c.rate_total, r->c.rate_total, t))
		return (false);
	return (true);
}

/* ---- The reflector ---------------------------------------------- */

int
stamp_refl_setconf(struct stamp_refl *r, const struct stamp_refl_conf *c)
{
	struct stamp_refl_conf	 n = *c;
	struct sess		*s;
	unsigned		 i;

	if (n.sess_max == 0)
		n.sess_max = STAMP_SESS_MAX;
	if (n.sess_idle == 0)
		n.sess_idle = STAMP_SESS_IDLE;
	if (n.rate > 0 && n.burst < 1)
		n.burst = n.rate * 2 < 1 ? 1 : n.rate * 2;
	/* The sessions, kept while their table stays as large. */
	if (!n.stateful || n.sess_max != r->nsessmax) {
		free(r->sess);
		r->sess = NULL;
		r->nsessmax = 0;
		r->nsess = 0;
		for (i = 0; i < SESS_BUCKETS; i++)
			r->bucket[i] = -1;
	}
	if (n.stateful && r->sess == NULL) {
		if ((s = calloc(n.sess_max, sizeof(*s))) == NULL)
			return (-1);
		r->sess = s;
		r->nsessmax = n.sess_max;
	}
	r->c = n;
	return (0);
}

struct stamp_refl *
stamp_refl_new(const struct stamp_refl_conf *c)
{
	struct stamp_refl	*r;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		return (NULL);
	r->key = arc4random();
	if (stamp_refl_setconf(r, c) == -1) {
		free(r);
		return (NULL);
	}
	return (r);
}

void
stamp_refl_free(struct stamp_refl *r)
{

	if (r == NULL)
		return;
	free(r->sess);
	free(r);
}

void
stamp_refl_stats(const struct stamp_refl *r, struct stamp_refl_stats *st)
{

	*st = r->st;
	st->sessions = r->nsess;
}

/*
 * The TLVs of a reply of len octets, copied from the request (RFC 8972
 * 4): the Timestamp Information TLV filled (the clock's source, how T2
 * and T3 are taken), any other but Extra Padding marked unrecognised
 * (U).  What follows the base is TLVs only when it is TLVs to its end,
 * none of type 0: anything else is a sender's padding (a TWAMP Light
 * sender's zeros, a pattern), copied as it is.
 */
static void
tlvs_reflect(uint8_t *out, size_t len, uint8_t sync, uint8_t ts_in,
    uint8_t ts_out)
{
	struct stamp_tlv	v;
	size_t			off, at;
	int			rc;

	off = STAMP_UNAUTH_LEN;
	while ((rc = stamp_tlv_next(out, len, &off, &v)) == 1)
		if (v.type == 0)
			return;
	if (rc == -1)
		return;
	off = STAMP_UNAUTH_LEN;
	for (;;) {
		at = off;
		if (stamp_tlv_next(out, len, &off, &v) != 1)
			break;
		if (v.type == STAMP_TLV_TSINFO && v.len >= 4) {
			out[at + 4] = sync;
			out[at + 5] = ts_in;
			out[at + 6] = sync;
			out[at + 7] = ts_out;
		} else if (v.type != STAMP_TLV_PAD)
			out[at] |= STAMP_TLV_U;
	}
}

/*
 * The reply to rx in out (outlen octets): its length, rx's, or -1 with
 * why it is not answered.  Its Timestamp (T3) is for the caller to set
 * last, with stamp_refl_send_time(), before it is sent.
 */
ssize_t
stamp_refl_reply(struct stamp_refl *r, const struct stamp_rx *rx,
    uint8_t *out, size_t outlen, enum stamp_drop *why)
{
	struct sockaddr_storage	 peer, local;
	const uint8_t		*in = rx->pkt;
	enum stamp_drop		 w;
	uint32_t		 seq;
	uint16_t		 ssid, port;
	uint8_t			 a[16];
	double			 now;

	now = rx->mono != 0 ? rx->mono : stamp_mono();
	w = STAMP_ANSWERED;
	if (rx->len < STAMP_UNAUTH_LEN)
		w = STAMP_DROP_SHORT;
	else if (rx->len > outlen)
		w = STAMP_DROP_NOMEM;
	else {
		addr16(rx->peer, a, &port);
		port = ntohs(port);
		if (port == 0 || port == r->c.port)
			w = STAMP_DROP_PORT;
		else if (!rate_ok(r, rx->peer, now))
			w = STAMP_DROP_RATE;
	}
	if (why != NULL)
		*why = w;
	if (w != STAMP_ANSWERED) {
		r->st.dropped[w]++;
		return (-1);
	}

	/* As long as the packet, never longer. */
	memset(out, 0, STAMP_UNAUTH_LEN);
	memcpy(out + STAMP_UNAUTH_LEN, in + STAMP_UNAUTH_LEN, rx->len -
	    STAMP_UNAUTH_LEN);
	/* The sender's SSID; 0 from a TWAMP Light sender (its MBZ). */
	ssid = (uint16_t)(in[14] << 8 | in[15]);
	if (r->c.stateful) {
		sa_copy(&peer, rx->peer);
		sa_copy(&local, rx->local);
		if (rx->local == NULL)
			local.ss_family = rx->peer->sa_family;
		seq = sess_seq(r, rx->tag, ssid, &peer, &local, now);
		out[0] = (uint8_t)(seq >> 24);
		out[1] = (uint8_t)(seq >> 16);
		out[2] = (uint8_t)(seq >> 8);
		out[3] = (uint8_t)seq;
	} else
		memcpy(out, in, 4);
	/* The Error Estimate, the clock's, looked at once a second. */
	if (r->clk.ee == 0 || now - r->clk_at >= 1) {
		stamp_clock_get(&r->clk);
		r->clk_at = now;
	}
	out[12] = (uint8_t)(r->clk.ee >> 8);
	out[13] = (uint8_t)r->clk.ee;
	out[14] = in[14];			/* SSID */
	out[15] = in[15];
	stamp_ts_put(out + 16, r->clk.ee, &rx->t2);	/* Receive Timestamp */
	memcpy(out + 24, in, 4);		/* Session-Sender Sequence */
	memcpy(out + 28, in + 4, 8);		/* ... Timestamp */
	memcpy(out + 36, in + 12, 2);		/* ... Error Estimate */
	out[40] = (uint8_t)(rx->ttl > 0 ? rx->ttl : 0);	/* ... TTL */
	tlvs_reflect(out, rx->len, r->clk.sync, rx->ts_in != 0 ? rx->ts_in :
	    STAMP_TSM_SW, r->c.ts_out != 0 ? r->c.ts_out : STAMP_TSM_SW);
	r->st.answered++;
	return ((ssize_t)rx->len);
}

/* The reply's Timestamp, T3, as late as can be: in the format its
 * Error Estimate says. */
void
stamp_refl_send_time(uint8_t *out, const struct timespec *t3)
{

	stamp_ts_put(out + 4, (uint16_t)(out[12] << 8 | out[13]), t3);
}
