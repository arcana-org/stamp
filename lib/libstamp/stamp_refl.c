/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The Session-Reflector's core (RFC 8762 4.3), with the Session-Sender
 * Identifier of RFC 8972 3, in both modes; it answers a TWAMP
 * Light Session-Sender (RFC 5357 Appendix I) that pads its packets to
 * 44 octets or more, the offsets being the same.  No socket here: a
 * packet as it came (struct stamp_rx) in, the reply out.
 *
 * Stateless, the reply's Sequence Number is the sender's; stateful, it
 * counts the packets reflected in the session (4.3.2), a session the
 * caller's tag (a FIB), the sender's address and port, the address the
 * packet came to and the SSID, so that the sender tells loss on the
 * way out from loss on the way back; a session also counts the requests
 * it received (one over a rate limit among them) and the replies it
 * made, for RFC 8972's Direct Measurement TLV, which a stateless
 * reflector answers with zeros.  A session made by an authenticated
 * request is one of its own, apart from an unauthenticated one of the
 * same key, which neither counts in it nor replaces it.  Sessions are
 * bounded (sess_max: when full, the oldest made unauthenticated
 * replaced, an authenticated one only by another and when there is no
 * other; an unauthenticated request finding them all authenticated
 * dropped, STAMP_DROP_FULL) and end after sess_idle seconds without a
 * packet.
 *
 * A reflector answers whoever writes a source address, so it is no
 * amplifier and no firehose.  Only a packet of STAMP_UNAUTH_LEN octets
 * or more is answered, the reply exactly as long, what follows the
 * base copied (padding, TLVs; the Timestamp Information, Class of
 * Service, Direct Measurement and Location TLVs filled, those not known
 * marked so).  Not one from port 0 nor from the reflector's own port (two reflectors made to answer each other
 * forever by one forged packet).  And no more replies to one source
 * than its token bucket allows, nor to all of them together than one
 * more: a source an IPv4 address (an IPv4-mapped IPv6 one alike) or an
 * IPv6 /64, whose 2^64 addresses one sender has; the sources' buckets a
 * table of RL_SLOTS, RL_WAYS a set, its hash keyed by a random secret
 * so that no sender chooses whom it displaces, a new source taking the
 * set's oldest.  A request whose HMAC verified draws from buckets apart
 * (its source's, and a total of its own as large), so that whoever
 * writes source addresses does not starve the authenticated sessions.
 *
 * Nor is the reflector made to spend its time on HMACs.  A request of
 * the authenticated layout costs one for each of its SSID's keys (looked
 * up by it, STAMP_KEYS_SSID_MAX at most: two while one is rotated, or
 * two sessions whose SSIDs, derived, are the same) and one for each key
 * for any SSID (STAMP_KEYS_ANY_MAX at most), 8 at most, whatever the
 * keys; and before any it draws a token from
 * its source's bucket of a class of its own, as large as its source's
 * (STAMP_DROP_PREAUTH when there is none), given back when the HMAC
 * verifies: the failures use it up, never the requests answered.
 * Whoever writes a sender's source address can drain it, as it can
 * that address's bucket of unauthenticated requests, and so starve the
 * sender's authenticated requests while it sends more failures than
 * the source's rate; but it touches no bucket of those verified, and
 * its flood costs the HMACs of that rate, where it cost those of every
 * key that might verify for each packet and, fast enough, every
 * session the CPU.  A flood of many sources costs a packet's at most.
 * No total of such tokens: one would let whoever writes any address
 * starve every authenticated session.
 *
 * The authenticated mode (RFC 8762 4.4): a request of its layout
 * (stamp_auth_layout()) is answered only when its HMAC verifies under
 * one of the reflector's keys for its SSID, or else under one for any
 * SSID, the first that does in the order they came; otherwise it is
 * dropped and counted
 * (STAMP_DROP_AUTH), never answered.  Its reply is of the same layout
 * under the same key, its HMAC made by stamp_refl_finish() once T3 is
 * in.  What follows its base must be well-formed TLVs to its end (no
 * octets left over, no header cut short, no length overlong, none of
 * type 0), else it is dropped as one failing authentication: nothing of
 * it was protected, and nothing can be flagged.  Its TLVs are looked at
 * when RFC 8972's HMAC TLV over them verifies (Extra Padding TLVs alone
 * need none); when it does not, or is missing, the reply carries them
 * as they came, each flagged I (4.8), and the HMAC TLV made again over
 * them.  A request of the unauthenticated layout is answered as before,
 * unless the reflector is authenticated only (STAMP_DROP_UNAUTH).
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
	uint32_t		 rx, tx;	/* received, sent: RFC 8972 4.5 */
	bool			 auth;		/* made authenticated */
	double			 last;
	int			 next;		/* in its bucket; -1 the end */
};

/* A source's buckets, one a class. */
#define	RL_UNAUTH	0		/* the unauthenticated requests' */
#define	RL_AUTH		1		/* those whose HMAC verified */
#define	RL_PRE		2		/* the authenticated layout's, before
					   any HMAC */

struct rl {
	uint8_t		 addr[16];	/* rl_key()'s */
	uint8_t		 cls;		/* RL_* */
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
	double			 auth_tokens, auth_last;	/* HMAC verified */
	struct stamp_clock	 clk;
	double			 clk_at;
	struct stamp_refl_stats	 st;
	int			 reply_tos;	/* the last reply's; -1 */
	/* The authenticated mode: the keys (those for any SSID first, nany
	 * of them, then by SSID), the request narrowed, and what the
	 * request being answered and the last reply are. */
	struct stamp_key	*keys;
	size_t			 nkeys, nany;
	uint8_t			*view;		/* STAMP_PKT_MAX */
	bool			 cur_auth, cur_tlv_bad;
	const struct stamp_key	*reply_key;	/* NULL: unauthenticated */
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

/*
 * The session, authenticated or not as auth, made if new and create,
 * else NULL.  The table full, the oldest made unauthenticated is
 * replaced; an authenticated one only for another, when there is no
 * unauthenticated one: NULL when there is none to replace.
 */
static struct sess *
sess_get(struct stamp_refl *r, int tag, uint16_t ssid,
    const struct sockaddr_storage *peer, const struct sockaddr_storage *local,
    double now, bool create, bool auth)
{
	struct sess	*s;
	unsigned	 b;
	int		 i, free_i, old_i, old_a;

	b = sess_hash(tag, ssid, peer);
	for (i = r->bucket[b]; i != -1; i = r->sess[i].next) {
		s = &r->sess[i];
		if (s->tag == tag && s->ssid == ssid && s->auth == auth &&
		    addr_eq(&s->peer, peer, true) && addr_eq(&s->local, local,
		    false)) {
			s->last = now;
			return (s);
		}
	}
	if (!create)
		return (NULL);
	free_i = old_i = old_a = -1;
	for (i = 0; i < (int)r->nsessmax; i++) {
		s = &r->sess[i];
		if (!s->used) {
			free_i = i;
			break;
		}
		if (s->auth) {
			if (old_a == -1 || s->last < r->sess[old_a].last)
				old_a = i;
		} else if (old_i == -1 || s->last < r->sess[old_i].last)
			old_i = i;
	}
	if (free_i == -1) {
		if (old_i == -1 && auth)
			old_i = old_a;
		if (old_i == -1)
			return (NULL);
		sess_unlink(r, old_i);
		free_i = old_i;
	}
	s = &r->sess[free_i];
	memset(s, 0, sizeof(*s));
	s->used = true;
	s->auth = auth;
	s->tag = tag;
	s->ssid = ssid;
	s->peer = *peer;
	s->local = *local;
	s->last = now;
	s->next = r->bucket[b];
	r->bucket[b] = free_i;
	r->nsess++;
	return (s);
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

/* A source, as its bucket is keyed: an IPv4 address mapped, an
 * IPv4-mapped IPv6 one alike, an IPv6 one's /64. */
static void
rl_key(const struct sockaddr *sa, uint8_t a[16])
{
	static const uint8_t	mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0xff, 0xff };
	uint16_t		port;

	addr16(sa, a, &port);
	if (memcmp(a, mapped, sizeof(mapped)) != 0)
		memset(a + 8, 0, 8);
}

/* peer's bucket of class cls, made if new: in the set's oldest, full. */
static struct rl *
rl_get(struct stamp_refl *r, const struct sockaddr *peer, uint8_t cls)
{
	struct rl	*b, *victim;
	uint8_t		 a[16];
	uint32_t	 h;
	int		 i, set;

	rl_key(peer, a);
	h = r->key;
	for (i = 0; i < 16; i++)
		h = (h ^ a[i]) * 16777619U;
	h = (h ^ cls) * 16777619U;
	set = (int)(h % (RL_SLOTS / RL_WAYS)) * RL_WAYS;
	victim = NULL;
	for (i = 0; i < RL_WAYS; i++) {
		b = &r->rl[set + i];
		if (b->last != 0 && b->cls == cls && memcmp(b->addr, a, 16) ==
		    0)
			return (b);
		if (victim == NULL || b->last < victim->last)
			victim = b;
	}
	b = victim;
	memcpy(b->addr, a, 16);
	b->cls = cls;
	b->last = 0;
	return (b);
}

/* A token for a reply to peer at t, from the buckets of the
 * authenticated requests when auth (their HMAC verified), else from the
 * others'. */
static bool
rate_ok(struct stamp_refl *r, const struct sockaddr *peer, double t,
    bool auth)
{
	struct rl	*b;

	if (r->c.rate > 0) {
		b = rl_get(r, peer, auth ? RL_AUTH : RL_UNAUTH);
		if (!bucket_take(&b->tokens, &b->last, r->c.rate, r->c.burst,
		    t))
			return (false);
	}
	if (r->c.rate_total > 0 && !(auth ? bucket_take(&r->auth_tokens,
	    &r->auth_last, r->c.rate_total, r->c.rate_total, t) :
	    bucket_take(&r->all_tokens, &r->all_last, r->c.rate_total,
	    r->c.rate_total, t)))
		return (false);
	return (true);
}

/*
 * A token for an HMAC of a request of the authenticated layout from
 * peer at t, before any is made, from its source's bucket of RL_PRE:
 * false when there is none; *bp the bucket, for pre_refund(), NULL when
 * a source has no limit.
 */
static bool
pre_take(struct stamp_refl *r, const struct sockaddr *peer, double t,
    struct rl **bp)
{
	struct rl	*b;

	*bp = NULL;
	if (r->c.rate <= 0)
		return (true);
	b = rl_get(r, peer, RL_PRE);
	if (!bucket_take(&b->tokens, &b->last, r->c.rate, r->c.burst, t))
		return (false);
	*bp = b;
	return (true);
}

/* Its token given back: the HMAC verified. */
static void
pre_refund(const struct stamp_refl *r, struct rl *b)
{

	if (b != NULL && (b->tokens += 1) > r->c.burst)
		b->tokens = r->c.burst;
}

/* ---- Keys ------------------------------------------------------- */

static int
key_cmp(const void *a, const void *b)
{
	int32_t	x = ((const struct stamp_key *)a)->ssid;
	int32_t	y = ((const struct stamp_key *)b)->ssid;

	return (x < y ? -1 : x > y);
}

/*
 * The keys of a configuration copied into *kp: those for any SSID first,
 * as they came (*nanyp of them, STAMP_KEYS_ANY_MAX at most), then by
 * SSID, an SSID's as they came (STAMP_KEYS_SSID_MAX at most); more:
 * E2BIG, an SSID past 65535: EINVAL.  0, or -1 with errno.
 */
static int
keys_index(const struct stamp_key *keys, size_t n, struct stamp_key **kp,
    size_t *nanyp)
{
	struct stamp_key	*k;
	size_t			 i, j, nany, run;

	*kp = NULL;
	*nanyp = 0;
	for (i = nany = 0; i < n; i++)
		if (keys[i].ssid == STAMP_SSID_ANY)
			nany++;
		else if (keys[i].ssid < 0 || keys[i].ssid > 65535) {
			errno = EINVAL;
			return (-1);
		}
	if (nany > STAMP_KEYS_ANY_MAX) {
		errno = E2BIG;
		return (-1);
	}
	if (n == 0)
		return (0);
	if ((k = calloc(n, sizeof(*k))) == NULL)
		return (-1);
	for (i = 0, j = nany, nany = 0; i < n; i++)
		if (keys[i].ssid == STAMP_SSID_ANY)
			k[nany++] = keys[i];
		else
			k[j++] = keys[i];
	/* Stable: an SSID's keys tried in the order they came. */
	if (n - nany > 1 && mergesort(k + nany, n - nany, sizeof(*k),
	    key_cmp) == -1) {
		stamp_keys_free(k, n);
		return (-1);
	}
	for (i = nany, run = 0; i < n; i++) {
		run = i > nany && k[i].ssid == k[i - 1].ssid ? run + 1 : 1;
		if (run > STAMP_KEYS_SSID_MAX) {
			stamp_keys_free(k, n);
			errno = E2BIG;
			return (-1);
		}
	}
	*kp = k;
	*nanyp = nany;
	return (0);
}

/* The first key of SSID ssid, *np of them, else NULL. */
static const struct stamp_key *
key_find(const struct stamp_refl *r, uint16_t ssid, size_t *np)
{
	const struct stamp_key	*f, *l, *end = r->keys + r->nkeys;
	struct stamp_key	 k;

	*np = 0;
	if (r->nkeys == r->nany)
		return (NULL);
	k.ssid = ssid;
	if ((f = bsearch(&k, r->keys + r->nany, r->nkeys - r->nany,
	    sizeof(k), key_cmp)) == NULL)
		return (NULL);
	while (f > r->keys + r->nany && f[-1].ssid == ssid)
		f--;
	for (l = f; l < end && l->ssid == ssid; l++)
		;
	*np = (size_t)(l - f);
	return (f);
}

/* ---- The reflector ---------------------------------------------- */

int
stamp_refl_setconf(struct stamp_refl *r, const struct stamp_refl_conf *c)
{
	struct stamp_refl_conf	 n = *c;
	struct stamp_key	*k = NULL;
	struct sess		*s;
	size_t			 nany;
	unsigned		 i;

	/* The keys, copied first: nothing changed when they cannot be. */
	if (n.nkeys > STAMP_KEYS_MAX) {
		errno = E2BIG;
		return (-1);
	}
	if (keys_index(n.keys, n.nkeys, &k, &nany) == -1)
		return (-1);
	if (n.nkeys > 0 && r->view == NULL && (r->view =
	    malloc(STAMP_PKT_MAX)) == NULL) {
		stamp_keys_free(k, n.nkeys);
		return (-1);
	}

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
		if ((s = calloc(n.sess_max, sizeof(*s))) == NULL) {
			stamp_keys_free(k, n.nkeys);
			return (-1);
		}
		r->sess = s;
		r->nsessmax = n.sess_max;
	}
	stamp_keys_free(r->keys, r->nkeys);
	r->keys = k;
	r->nkeys = n.nkeys;
	r->nany = nany;
	r->reply_key = NULL;
	n.keys = k;
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
	r->reply_tos = -1;
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
	stamp_keys_free(r->keys, r->nkeys);
	free(r->view);
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
 * The Class of Service TLV's value (RFC 8972 4.4) at v, of a request
 * that came with rx->tos: DSCP2 and ECN what it came with, and the
 * reply to carry DSCP1 unless the configuration refuses it, else the
 * request's DSCP, RP 1.
 */
static void
cos_reflect(struct stamp_refl *r, const struct stamp_rx *rx, uint8_t *v)
{
	uint8_t	dscp1, dscp2, ecn, rp;

	dscp1 = v[0] >> 2;
	dscp2 = rx->tos >= 0 ? (uint8_t)(rx->tos >> 2) : 0;
	ecn = rx->tos >= 0 ? (uint8_t)(rx->tos & 0x03) : 0;
	if (r->c.dscp_deny & ((uint64_t)1 << dscp1)) {
		rp = 1;
		r->reply_tos = rx->tos >= 0 ? rx->tos & 0xfc : -1;
	} else {
		rp = 0;
		r->reply_tos = dscp1 << 2;
	}
	v[0] = (uint8_t)(dscp1 << 2 | dscp2 >> 4);
	v[1] = (uint8_t)((dscp2 & 0x0f) << 4 | ecn << 2 | rp);
	v[2] = v[3] = 0;
}

/* An address's octets, an IPv4 one's 4 or an IPv6 one's 16, into a
 * Location sub-TLV's value v (16 octets, zero first; all zero when
 * hidden or not known); its type, t4 or t6 by the packet's family. */
static uint8_t
loc_put(uint8_t *v, const struct sockaddr *sa, uint8_t t4, uint8_t t6,
    int af, bool hide)
{

	memset(v, 0, 16);
	if (sa != NULL && !hide && sa->sa_family == AF_INET)
		memcpy(v, &((const struct sockaddr_in *)(const void *)sa)->
		    sin_addr, 4);
	else if (sa != NULL && !hide && sa->sa_family == AF_INET6)
		memcpy(v, &((const struct sockaddr_in6 *)(const void *)sa)->
		    sin6_addr, 16);
	return (af == AF_INET ? t4 : t6);
}

/*
 * The Location TLV's value v (vlen octets; RFC 8972 4.2): the ports the
 * request came to and from, and each sub-TLV asking for an address
 * answered in the packet's family, the source the sender's address as
 * it reached here, the destination the one it came to (zero when not
 * known); a source MAC (no UDP socket sees it) answered as an EUI-64
 * of zero; another marked unrecognised.  The ports and addresses zero
 * when the configuration hides them.  false when its sub-TLVs go past
 * it, nothing changed.
 */
static bool
loc_reflect(struct stamp_refl *r, const struct stamp_rx *rx, uint8_t *v,
    uint16_t vlen)
{
	uint16_t	dport, sport, slen;
	uint8_t		*p;
	size_t		at;
	int		af = rx->peer->sa_family;
	bool		hide = r->c.loc_hide;

	for (at = 4; at < vlen; at += 4 + (size_t)slen) {
		if (vlen - at < 4)
			return (false);
		slen = (uint16_t)(v[at + 2] << 8 | v[at + 3]);
		if (vlen - at - 4 < slen)
			return (false);
	}
	dport = hide ? 0 : r->c.port;
	if (!hide && rx->local != NULL && stamp_sa_port(rx->local) != 0)
		dport = stamp_sa_port(rx->local);
	sport = hide ? 0 : stamp_sa_port(rx->peer);
	v[0] = (uint8_t)(dport >> 8);
	v[1] = (uint8_t)dport;
	v[2] = (uint8_t)(sport >> 8);
	v[3] = (uint8_t)sport;
	for (at = 4; at < vlen; at += 4 + (size_t)slen) {
		p = v + at;
		slen = (uint16_t)(p[2] << 8 | p[3]);
		/* U, M and I 0 for what is known (RFC 8972 4.2), U else. */
		p[0] &= ~(STAMP_TLV_U | STAMP_TLV_M | STAMP_TLV_I);
		if (p[1] == STAMP_SUB_SRCIP && slen == 16)
			p[1] = loc_put(p + 4, rx->peer, STAMP_SUB_SRCIP4,
			    STAMP_SUB_SRCIP6, af, hide);
		else if (p[1] == STAMP_SUB_DSTIP && slen == 16)
			p[1] = loc_put(p + 4, rx->local, STAMP_SUB_DSTIP4,
			    STAMP_SUB_DSTIP6, af, hide);
		else if (p[1] == STAMP_SUB_SRCMAC && slen == 8) {
			p[1] = STAMP_SUB_EUI64;
			memset(p + 4, 0, 8);
		} else
			p[0] |= STAMP_TLV_U;
	}
	return (true);
}

/* The Direct Measurement TLV's value v (RFC 8972 4.5): the sender's
 * counter as it is, the session's received and sent; 0 each when
 * stateless (no session to count in). */
static void
dm_reflect(const struct sess *s, uint8_t *v)
{
	uint32_t	rx = s != NULL ? s->rx : 0, tx = s != NULL ? s->tx : 0;

	v[4] = (uint8_t)(rx >> 24);
	v[5] = (uint8_t)(rx >> 16);
	v[6] = (uint8_t)(rx >> 8);
	v[7] = (uint8_t)rx;
	v[8] = (uint8_t)(tx >> 24);
	v[9] = (uint8_t)(tx >> 16);
	v[10] = (uint8_t)(tx >> 8);
	v[11] = (uint8_t)tx;
}

/*
 * The TLVs of a reply of len octets, copied from the request (RFC 8972
 * 4): the Timestamp Information TLV filled (the clock's source, how T2
 * and T3 are taken), the Class of Service TLV too (cos_reflect()), the
 * Direct Measurement TLV (dm_reflect()) and the Location TLV
 * (loc_reflect()); one of them not as long as its kind is (Timestamp
 * Information 4 or more, Class of Service 4, Direct Measurement 12,
 * Location 4 or more) or whose sub-TLVs go past it marked malformed
 * (M), any other but Extra Padding marked unrecognised (U).  What follows the base is TLVs only when it
 * is TLVs to its end, none of type 0: anything else is a sender's
 * padding (a TWAMP Light sender's zeros, a pattern), copied as it is.
 */
static void
tlvs_reflect(struct stamp_refl *r, const struct stamp_rx *rx,
    const struct sess *s, uint8_t *out, size_t len)
{
	struct stamp_tlv	v;
	size_t			off, at;
	uint8_t			sync = r->clk.sync, ts_in, ts_out;
	int			rc;

	ts_in = rx->ts_in != 0 ? rx->ts_in : STAMP_TSM_SW;
	ts_out = r->c.ts_out != 0 ? r->c.ts_out : STAMP_TSM_SW;
	off = STAMP_UNAUTH_LEN;
	while ((rc = stamp_tlv_next(out, len, &off, &v)) == 1)
		if (v.type == 0)
			return;
	if (rc == -1)
		return;
	off = STAMP_UNAUTH_LEN;
	/* Authenticated, the HMAC TLV wrong: none looked at, each I. */
	if (r->cur_auth && r->cur_tlv_bad) {
		for (;;) {
			at = off;
			if (stamp_tlv_next(out, len, &off, &v) != 1)
				break;
			out[at] = (uint8_t)((out[at] & ~(STAMP_TLV_U |
			    STAMP_TLV_M)) | STAMP_TLV_I);
		}
		return;
	}
	for (;;) {
		at = off;
		if (stamp_tlv_next(out, len, &off, &v) != 1)
			break;
		/* The sender's U 1 (RFC 8972 4): each flag 0 but where the
		 * TLV is not known (U), malformed (M). */
		out[at] &= ~(STAMP_TLV_U | STAMP_TLV_M | STAMP_TLV_I);
		switch (v.type) {
		case STAMP_TLV_PAD:
			break;
		case STAMP_TLV_HMAC:
			/* Made again over the reply's (refl_auth()); of no
			 * meaning unauthenticated. */
			if (!r->cur_auth)
				out[at] |= STAMP_TLV_U;
			break;
		case STAMP_TLV_TSINFO:
			if (v.len < 4) {
				out[at] |= STAMP_TLV_M;
				break;
			}
			out[at + 4] = sync;
			out[at + 5] = ts_in;
			out[at + 6] = sync;
			out[at + 7] = ts_out;
			break;
		case STAMP_TLV_COS:
			if (v.len != 4) {
				out[at] |= STAMP_TLV_M;
				break;
			}
			cos_reflect(r, rx, out + at + 4);
			break;
		case STAMP_TLV_DM:
			if (v.len != 12) {
				out[at] |= STAMP_TLV_M;
				break;
			}
			dm_reflect(s, out + at + 4);
			break;
		case STAMP_TLV_LOCATION:
			if (v.len < 4 || !loc_reflect(r, rx, out + at + 4,
			    v.len))
				out[at] |= STAMP_TLV_M;
			break;
		default:
			out[at] |= STAMP_TLV_U;
		}
	}
}

/* The TOS or traffic class octet the reply stamp_refl_reply() made
 * last is to be sent with, a Class of Service TLV's: -1 when it had
 * none, the socket's own. */
int
stamp_refl_reply_tos(const struct stamp_refl *r)
{

	return (r->reply_tos);
}

/* The reply to rx of the unauthenticated layout. */
static ssize_t
refl_core(struct stamp_refl *r, const struct stamp_rx *rx, uint8_t *out,
    size_t outlen, enum stamp_drop *why)
{
	struct sockaddr_storage	 peer, local;
	struct sess		*s = NULL;
	const uint8_t		*in = rx->pkt;
	enum stamp_drop		 w;
	uint32_t		 seq;
	uint16_t		 ssid, port;
	uint8_t			 a[16];
	double			 now;

	now = rx->mono != 0 ? rx->mono : stamp_mono();
	r->reply_tos = -1;
	/* The sender's SSID; 0 from a TWAMP Light sender (its MBZ). */
	ssid = rx->len >= STAMP_UNAUTH_LEN ? (uint16_t)(in[14] << 8 | in[15]) :
	    0;
	if (r->c.stateful) {
		sa_copy(&peer, rx->peer);
		sa_copy(&local, rx->local);
		if (rx->local == NULL)
			local.ss_family = rx->peer->sa_family;
	}
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
		else if (!rate_ok(r, rx->peer, now, r->cur_auth))
			w = STAMP_DROP_RATE;
		else if (r->c.stateful && (s = sess_get(r, rx->tag, ssid,
		    &peer, &local, now, true, r->cur_auth)) == NULL)
			w = STAMP_DROP_FULL;
	}
	if (why != NULL)
		*why = w;
	/* Over a rate, a session's request is still one it received. */
	if (w == STAMP_DROP_RATE && r->c.stateful && (s = sess_get(r, rx->tag,
	    ssid, &peer, &local, now, false, r->cur_auth)) != NULL)
		s->rx++;
	if (w != STAMP_ANSWERED) {
		r->st.dropped[w]++;
		return (-1);
	}

	/* As long as the packet, never longer. */
	memset(out, 0, STAMP_UNAUTH_LEN);
	memcpy(out + STAMP_UNAUTH_LEN, in + STAMP_UNAUTH_LEN, rx->len -
	    STAMP_UNAUTH_LEN);
	if (r->c.stateful) {
		seq = s->seq++;
		s->rx++;
		s->tx++;
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
	tlvs_reflect(r, rx, s, out, rx->len);
	r->st.answered++;
	return ((ssize_t)rx->len);
}

/* A drop before the core: counted, said. */
static ssize_t
refl_drop(struct stamp_refl *r, enum stamp_drop w, enum stamp_drop *why)
{

	if (why != NULL)
		*why = w;
	r->st.dropped[w]++;
	return (-1);
}

/*
 * A request of the authenticated layout: its key the first of its
 * SSID's, else of those for any SSID, its HMAC verifies under, a token
 * of its source's
 * taken before the first HMAC (pre_take()); the core's reply to it
 * narrowed, widened again, its HMAC TLV made.
 */
static ssize_t
refl_auth(struct stamp_refl *r, const struct stamp_rx *rx, uint8_t *out,
    size_t outlen, enum stamp_drop *why)
{
	const struct stamp_key	*k = NULL, *own;
	struct stamp_rx		 nrx;
	struct rl		*b;
	ssize_t			 n;
	size_t			 i, nown;

	own = key_find(r, stamp_auth_ssid(rx->pkt), &nown);
	if (own == NULL && r->nany == 0)
		return (refl_drop(r, STAMP_DROP_AUTH, why));
	if (!pre_take(r, rx->peer, rx->mono != 0 ? rx->mono : stamp_mono(),
	    &b))
		return (refl_drop(r, STAMP_DROP_PREAUTH, why));
	for (i = 0; i < nown && k == NULL; i++)
		if (stamp_auth_verify(&own[i], rx->pkt, rx->len))
			k = &own[i];
	for (i = 0; i < r->nany && k == NULL; i++)
		if (stamp_auth_verify(&r->keys[i], rx->pkt, rx->len))
			k = &r->keys[i];
	if (k == NULL)
		return (refl_drop(r, STAMP_DROP_AUTH, why));
	pre_refund(r, b);
	if (rx->len > outlen || rx->len > STAMP_PKT_MAX)
		return (refl_drop(r, STAMP_DROP_NOMEM, why));
	switch (stamp_auth_tlv_verify(k, rx->pkt, rx->len, STAMP_AUTH_LEN)) {
	case -1:
		/* Not TLVs after the base: unprotected octets. */
		return (refl_drop(r, STAMP_DROP_AUTH, why));
	case 0:
		r->cur_tlv_bad = true;
		break;
	default:
		r->cur_tlv_bad = false;
	}
	memcpy(r->view, rx->pkt, rx->len);
	stamp_auth_narrow(r->view, rx->len, false);
	nrx = *rx;
	nrx.pkt = r->view;
	nrx.len = rx->len - (STAMP_AUTH_LEN - STAMP_UNAUTH_LEN);
	r->cur_auth = true;
	n = refl_core(r, &nrx, out, outlen, why);
	r->cur_auth = false;
	if (n < 0)
		return (n);
	if (r->cur_tlv_bad)
		r->st.tlv_failed++;
	stamp_auth_widen(out, (size_t)n, true);
	n += STAMP_AUTH_LEN - STAMP_UNAUTH_LEN;
	(void)stamp_auth_tlv_seal(k, out, (size_t)n, STAMP_AUTH_LEN);
	r->reply_key = k;
	return (n);
}

/*
 * The reply to rx in out (outlen octets): its length, rx's, or -1 with
 * why it is not answered.  Its Timestamp (T3) is for the caller to set
 * last, with stamp_refl_finish(), before it is sent: an authenticated
 * reply's HMAC with it.
 */
ssize_t
stamp_refl_reply(struct stamp_refl *r, const struct stamp_rx *rx,
    uint8_t *out, size_t outlen, enum stamp_drop *why)
{

	r->reply_key = NULL;
	r->reply_tos = -1;
	if (rx->len >= STAMP_AUTH_LEN && stamp_auth_layout(rx->pkt, rx->len))
		return (refl_auth(r, rx, out, outlen, why));
	if (r->c.auth_only && rx->len >= STAMP_UNAUTH_LEN)
		return (refl_drop(r, STAMP_DROP_UNAUTH, why));
	return (refl_core(r, rx, out, outlen, why));
}

/* The reply's Timestamp, T3, as late as can be: in the format its
 * Error Estimate says (the unauthenticated layout). */
void
stamp_refl_send_time(uint8_t *out, const struct timespec *t3)
{

	stamp_ts_put(out + 4, (uint16_t)(out[12] << 8 | out[13]), t3);
}

/*
 * The last reply stamp_refl_reply() made (out, len octets) finished:
 * its Timestamp T3, and, authenticated, its HMAC under the request's
 * key.  0, or -1.
 */
int
stamp_refl_finish(const struct stamp_refl *r, uint8_t *out, size_t len,
    const struct timespec *t3)
{

	if (r->reply_key == NULL) {
		stamp_refl_send_time(out, t3);
		return (0);
	}
	stamp_auth_send_time(out, t3);
	return (stamp_auth_seal(r->reply_key, out, len));
}
