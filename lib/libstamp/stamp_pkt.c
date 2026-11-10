/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The test packets of the unauthenticated mode, both ways (RFC 8762
 * 4.2.1 and 4.3.1), the octets 14 and 15 the Session-Sender Identifier
 * (RFC 8972 3), and the TLVs that may follow (RFC 8972 4): a flags
 * octet (U, M, I), the type, a 16-bit length and the value; the
 * Timestamp Information TLV (4.3, type 3) four octets, the sync source
 * and timestamping method of T2, then of T3; the Class of Service TLV
 * (4.4, type 4) four, DSCP1 (6 bits), DSCP2 (6), ECN (2), RP (2) and
 * 16 reserved; the Direct Measurement TLV (4.5, type 5) twelve, the
 * sender's transmit counter and the reflector's receive and transmit
 * counters; the Location TLV (4.2, type 2) the destination and source
 * ports and sub-TLVs, each laid out as a TLV, the sender's asking for
 * an address (Destination IP Address, 4; Source IP Address, 7; 16
 * octets of zero) and the reflector's answering it in the packet's
 * family (5 or 6, 8 or 9: an IPv4 address in the first 4).  The
 * authenticated mode's (4.2.2, 4.3.2) would be STAMP_AUTH_LEN octets
 * and an HMAC: not yet.
 *
 * Sender:	0 seq, 4 timestamp, 12 error estimate, 14 SSID, 16 MBZ
 * Reflector:	0 seq, 4 timestamp, 12 error estimate, 14 SSID,
 *		16 receive timestamp, 24 sender's seq, 28 sender's
 *		timestamp, 36 sender's error estimate, 38 MBZ, 40 sender's
 *		TTL, 41 MBZ
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "stamp.h"

static uint32_t
get32(const uint8_t *p)
{

	return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | p[3]);
}

static uint16_t
get16(const uint8_t *p)
{

	return ((uint16_t)(p[0] << 8 | p[1]));
}

static void
put32(uint8_t *p, uint32_t v)
{

	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static void
put16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

/* The base packet into buf (len, at least STAMP_UNAUTH_LEN): its MBZ
 * zero, what follows it as it is.  0, or -1 with errno. */
int
stamp_test_encode(uint8_t *buf, size_t len, const struct stamp_test *t)
{

	if (len < STAMP_UNAUTH_LEN) {
		errno = EMSGSIZE;
		return (-1);
	}
	memset(buf, 0, STAMP_UNAUTH_LEN);
	put32(buf, t->seq);
	stamp_ts_put(buf + 4, t->ee, &t->ts);
	put16(buf + 12, t->ee);
	put16(buf + 14, t->ssid);
	return (0);
}

int
stamp_test_decode(const uint8_t *buf, size_t len, struct stamp_test *t)
{

	if (len < STAMP_UNAUTH_LEN) {
		errno = EMSGSIZE;
		return (-1);
	}
	t->seq = get32(buf);
	t->ee = get16(buf + 12);
	stamp_ts_get(buf + 4, t->ee, &t->ts);
	t->ssid = get16(buf + 14);
	return (0);
}

int
stamp_reflected_decode(const uint8_t *buf, size_t len,
    struct stamp_reflected *r)
{
	static const uint8_t	zero[3];

	if (len < STAMP_UNAUTH_LEN) {
		errno = EMSGSIZE;
		return (-1);
	}
	r->seq = get32(buf);
	r->ee = get16(buf + 12);
	stamp_ts_get(buf + 4, r->ee, &r->ts);
	r->ssid = get16(buf + 14);
	stamp_ts_get(buf + 16, r->ee, &r->rx);
	r->sseq = get32(buf + 24);
	r->see = get16(buf + 36);
	stamp_ts_get(buf + 28, r->see, &r->sts);
	r->sttl = buf[40];
	r->mbz_ok = memcmp(buf + 38, zero, 2) == 0 &&
	    memcmp(buf + 41, zero, 3) == 0;
	return (0);
}

/*
 * The TLV at *off (STAMP_UNAUTH_LEN first) of a packet of len octets,
 * *off moved past it: 1, none left 0, or -1 when its length goes past
 * the packet (errno EBADMSG).
 */
int
stamp_tlv_next(const uint8_t *pkt, size_t len, size_t *off,
    struct stamp_tlv *tlv)
{
	size_t	at = *off < STAMP_UNAUTH_LEN ? STAMP_UNAUTH_LEN : *off;

	if (at >= len)
		return (0);
	if (len - at < 4) {
		errno = EBADMSG;
		return (-1);
	}
	tlv->flags = pkt[at];
	tlv->type = pkt[at + 1];
	tlv->len = get16(pkt + at + 2);
	if (len - at - 4 < tlv->len) {
		errno = EBADMSG;
		return (-1);
	}
	tlv->value = pkt + at + 4;
	*off = at + 4 + tlv->len;
	return (1);
}

/*
 * A TLV of type and vlen octets of value (NULL: what is there left as
 * it is) at *off (STAMP_UNAUTH_LEN first) of a packet of len octets,
 * its flags 0, *off moved past it: 0, or -1 with errno EMSGSIZE when
 * it does not fit.
 */
int
stamp_tlv_put(uint8_t *pkt, size_t len, size_t *off, uint8_t type,
    const void *value, uint16_t vlen)
{
	size_t	at = *off < STAMP_UNAUTH_LEN ? STAMP_UNAUTH_LEN : *off;

	if (at > len || len - at < (size_t)STAMP_TLV_HDR + vlen) {
		errno = EMSGSIZE;
		return (-1);
	}
	pkt[at] = 0;
	pkt[at + 1] = type;
	put16(pkt + at + 2, vlen);
	if (value != NULL)
		memcpy(pkt + at + 4, value, vlen);
	*off = at + 4 + vlen;
	return (0);
}

/*
 * The first TLV of type, of vlen octets or more, of a reflected packet:
 * 1 when the reflector filled it (neither U nor M: it knew it, as it
 * was), 0 when there is none or it did not, -1 when the TLVs go past
 * the packet (EBADMSG).
 */
static int
tlv_find(const uint8_t *pkt, size_t len, uint8_t type, uint16_t vlen,
    struct stamp_tlv *v)
{
	size_t	off = STAMP_UNAUTH_LEN;
	int	rc;

	while ((rc = stamp_tlv_next(pkt, len, &off, v)) == 1) {
		if (v->type != type || v->len < vlen)
			continue;
		return ((v->flags & (STAMP_TLV_U | STAMP_TLV_M)) ? 0 : 1);
	}
	return (rc);
}

/* The Timestamp Information TLV of a reflected packet into ti: as
 * tlv_find(). */
int
stamp_tsinfo_find(const uint8_t *pkt, size_t len, struct stamp_tsinfo *ti)
{
	struct stamp_tlv	v;
	int			rc;

	if ((rc = tlv_find(pkt, len, STAMP_TLV_TSINFO, 4, &v)) != 1)
		return (rc);
	ti->sync_in = v.value[0];
	ti->ts_in = v.value[1];
	ti->sync_out = v.value[2];
	ti->ts_out = v.value[3];
	return (1);
}

/* The Class of Service TLV of a reflected packet into cos: as
 * tlv_find(). */
int
stamp_cos_find(const uint8_t *pkt, size_t len, struct stamp_cos *cos)
{
	struct stamp_tlv	v;
	int			rc;

	if ((rc = tlv_find(pkt, len, STAMP_TLV_COS, 4, &v)) != 1)
		return (rc);
	cos->dscp1 = v.value[0] >> 2;
	cos->dscp2 = (uint8_t)((v.value[0] & 0x03) << 4 | v.value[1] >> 4);
	cos->ecn = (v.value[1] >> 2) & 0x03;
	cos->rp = v.value[1] & 0x03;
	return (1);
}

/* The Direct Measurement TLV of a reflected packet into dm: as
 * tlv_find(), and 0 too when the reflector counted nothing (R_RxC 0:
 * a stateless one; one that counts has this request among them). */
int
stamp_dm_find(const uint8_t *pkt, size_t len, struct stamp_dm *dm)
{
	struct stamp_tlv	v;
	int			rc;

	if ((rc = tlv_find(pkt, len, STAMP_TLV_DM, 12, &v)) != 1)
		return (rc);
	dm->s_tx = get32(v.value);
	dm->r_rx = get32(v.value + 4);
	dm->r_tx = get32(v.value + 8);
	return (dm->r_rx != 0 ? 1 : 0);
}

/* An address of family af (alen octets at a) and port into ss; left
 * unsaid (family 0) when it is all zeros. */
static void
loc_addr(struct sockaddr_storage *ss, int af, const uint8_t *a, size_t alen,
    uint16_t port)
{
	static const uint8_t	zero[16];

	memset(ss, 0, sizeof(*ss));
	if (memcmp(a, zero, alen) == 0)
		return;
	if (af == AF_INET) {
		struct sockaddr_in	*s4 = (struct sockaddr_in *)(void *)ss;

		s4->sin_family = AF_INET;
		s4->sin_len = sizeof(*s4);
		memcpy(&s4->sin_addr, a, 4);
		s4->sin_port = htons(port);
	} else {
		struct sockaddr_in6	*s6 = (struct sockaddr_in6 *)(void *)ss;

		s6->sin6_family = AF_INET6;
		s6->sin6_len = sizeof(*s6);
		memcpy(&s6->sin6_addr, a, 16);
		s6->sin6_port = htons(port);
	}
}

/*
 * The Location TLV of a reflected packet into loc (RFC 8972 4.2): the
 * ports, and the addresses of its sub-TLVs as the reflector answered
 * them (Destination and Source IPv4 or IPv6 Address).  As tlv_find();
 * its sub-TLVs going past it, malformed: 0.
 */
int
stamp_location_find(const uint8_t *pkt, size_t len,
    struct stamp_location *loc)
{
	struct stamp_tlv	 v;
	const uint8_t		*p;
	uint16_t		 dport, sport, slen;
	size_t			 at;
	int			 rc;

	memset(loc, 0, sizeof(*loc));
	if ((rc = tlv_find(pkt, len, STAMP_TLV_LOCATION, 4, &v)) != 1)
		return (rc);
	dport = get16(v.value);
	sport = get16(v.value + 2);
	for (at = 4; at < v.len; at += 4 + (size_t)slen) {
		if (v.len - at < 4)
			return (0);
		p = v.value + at;
		slen = get16(p + 2);
		if (v.len - at - 4 < slen)
			return (0);
		if (p[0] & (STAMP_TLV_U | STAMP_TLV_M))
			continue;
		if (p[1] == STAMP_SUB_DSTIP4 && slen >= 4)
			loc_addr(&loc->dst, AF_INET, p + 4, 4, dport);
		else if (p[1] == STAMP_SUB_DSTIP6 && slen >= 16)
			loc_addr(&loc->dst, AF_INET6, p + 4, 16, dport);
		else if (p[1] == STAMP_SUB_SRCIP4 && slen >= 4)
			loc_addr(&loc->src, AF_INET, p + 4, 4, sport);
		else if (p[1] == STAMP_SUB_SRCIP6 && slen >= 16)
			loc_addr(&loc->src, AF_INET6, p + 4, 16, sport);
	}
	return (1);
}

/* a and b the same address, and port unless b's is 0. */
static bool
sa_same(const struct sockaddr_storage *a, const struct sockaddr *b)
{
	const struct sockaddr_in	*a4, *b4;
	const struct sockaddr_in6	*a6, *b6;

	if (a->ss_family != b->sa_family)
		return (false);
	if (b->sa_family == AF_INET) {
		a4 = (const struct sockaddr_in *)(const void *)a;
		b4 = (const struct sockaddr_in *)(const void *)b;
		return (a4->sin_addr.s_addr == b4->sin_addr.s_addr &&
		    (b4->sin_port == 0 || a4->sin_port == b4->sin_port));
	}
	if (b->sa_family == AF_INET6) {
		a6 = (const struct sockaddr_in6 *)(const void *)a;
		b6 = (const struct sockaddr_in6 *)(const void *)b;
		return (memcmp(&a6->sin6_addr, &b6->sin6_addr, 16) == 0 &&
		    (b6->sin6_port == 0 || a6->sin6_port == b6->sin6_port));
	}
	return (false);
}

/*
 * What loc says was rewritten between this end and the reflector:
 * STAMP_NAT_SRC when the source it saw is not self (the address and
 * port this end sent from; port 0 not compared), STAMP_NAT_DST when the
 * destination is not far (the address and port it sent to); what loc
 * does not say, or self or far NULL, not compared.
 */
int
stamp_location_nat(const struct stamp_location *loc,
    const struct sockaddr *self, const struct sockaddr *far)
{
	int	nat = 0;

	if (self != NULL && loc->src.ss_family != 0 && !sa_same(&loc->src,
	    self))
		nat |= STAMP_NAT_SRC;
	if (far != NULL && loc->dst.ss_family != 0 && !sa_same(&loc->dst,
	    far))
		nat |= STAMP_NAT_DST;
	return (nat);
}
