/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The authenticated mode (RFC 8762 4.2.2, 4.3.2, 4.4; RFC 8972 3 and
 * 4.8): the larger layout, 112 octets, its fields apart with MBZ
 * between them and an HMAC over the first 96, HMAC-SHA-256 truncated to
 * 128 bits (libcrypto), the TLVs after it and RFC 8972's HMAC TLV
 * (type 8) after them, Extra Padding aside, over the Sequence Number
 * and the TLVs before it.  A key is the session's, said by its SSID;
 * the keys come from a file only its owner reads.
 *
 * The two cores work on the unauthenticated layout: a packet of the
 * authenticated mode is narrowed to it (its fields moved where the
 * 44-octet packet has them, its TLVs after them) and the reply widened
 * back, the HMACs made over the wide one.
 *
 * Sender:	0 seq, 4 MBZ, 16 timestamp, 24 error estimate, 26 SSID,
 *		28 MBZ, 96 HMAC
 * Reflector:	0 seq, 4 MBZ, 16 timestamp, 24 error estimate, 26 SSID,
 *		28 MBZ, 32 receive timestamp, 40 MBZ, 48 sender's seq,
 *		52 MBZ, 64 sender's timestamp, 72 sender's error estimate,
 *		74 MBZ, 80 sender's TTL, 81 MBZ, 96 HMAC
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "stamp.h"

#define	A_TS		16
#define	A_EE		24
#define	A_SSID		26
#define	A_RX		32
#define	A_SSEQ		48
#define	A_STS		64
#define	A_SEE		72
#define	A_TTL		80
#define	A_HMAC		96
#define	WIDE		(STAMP_AUTH_LEN - STAMP_UNAUTH_LEN)
#define	KEYFILE_MAX	(1024 * 1024)

static pthread_once_t	 mac_once = PTHREAD_ONCE_INIT;
static EVP_MAC		*mac;

static void
mac_fetch(void)
{

	mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
}

/*
 * HMAC-SHA-256 of a then b (blen 0: a alone) under key k, truncated to
 * its first 16 octets, into out: 0, or -1 (errno EINVAL: no HMAC).
 */
int
stamp_hmac(const struct stamp_key *k, const uint8_t *a, size_t alen,
    const uint8_t *b, size_t blen, uint8_t *out)
{
	EVP_MAC_CTX	*c;
	OSSL_PARAM	 p[2];
	uint8_t		 full[EVP_MAX_MD_SIZE];
	size_t		 n = 0;
	int		 ok;

	(void)pthread_once(&mac_once, mac_fetch);
	if (mac == NULL || (c = EVP_MAC_CTX_new(mac)) == NULL) {
		errno = EINVAL;
		return (-1);
	}
	p[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
	    (char *)(uintptr_t)"SHA256", 0);
	p[1] = OSSL_PARAM_construct_end();
	ok = EVP_MAC_init(c, k->key, k->len, p) == 1 &&
	    EVP_MAC_update(c, a, alen) == 1 && (blen == 0 ||
	    EVP_MAC_update(c, b, blen) == 1) &&
	    EVP_MAC_final(c, full, &n, sizeof(full)) == 1 && n >= STAMP_HMAC_LEN;
	EVP_MAC_CTX_free(c);
	if (ok)
		memcpy(out, full, STAMP_HMAC_LEN);
	OPENSSL_cleanse(full, sizeof(full));
	if (!ok) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

/* The base packet's HMAC (the first 96 octets) is the one in it. */
bool
stamp_auth_verify(const struct stamp_key *k, const uint8_t *pkt, size_t len)
{
	uint8_t	h[STAMP_HMAC_LEN];
	bool	ok;

	if (len < STAMP_AUTH_LEN || stamp_hmac(k, pkt, A_HMAC, NULL, 0, h) ==
	    -1)
		return (false);
	ok = CRYPTO_memcmp(h, pkt + A_HMAC, STAMP_HMAC_LEN) == 0;
	OPENSSL_cleanse(h, sizeof(h));
	return (ok);
}

/* The base packet's HMAC made. */
int
stamp_auth_seal(const struct stamp_key *k, uint8_t *pkt, size_t len)
{

	if (len < STAMP_AUTH_LEN) {
		errno = EMSGSIZE;
		return (-1);
	}
	return (stamp_hmac(k, pkt, A_HMAC, NULL, 0, pkt + A_HMAC));
}

/*
 * A packet in the authenticated layout: 112 octets or more, the twelve
 * after the Sequence Number zero (MBZ; the unauthenticated layout's
 * Timestamp there, never zero from a running clock).
 */
bool
stamp_auth_layout(const uint8_t *pkt, size_t len)
{
	static const uint8_t	zero[12];

	return (len >= STAMP_AUTH_LEN && memcmp(pkt + 4, zero, 12) == 0);
}

/* The SSID of a packet of the authenticated layout. */
uint16_t
stamp_auth_ssid(const uint8_t *pkt)
{

	return ((uint16_t)(pkt[A_SSID] << 8 | pkt[A_SSID + 1]));
}

/*
 * A packet of len octets (112 or more) of the authenticated layout, in
 * place, into the unauthenticated one, len - 68 octets: its fields
 * where the 44-octet packet has them, a reflected one's (refl) too,
 * the MBZ zero, the TLVs after them.
 */
void
stamp_auth_narrow(uint8_t *pkt, size_t len, bool refl)
{
	uint8_t	b[STAMP_UNAUTH_LEN];

	memset(b, 0, sizeof(b));
	memcpy(b, pkt, 4);
	memcpy(b + 4, pkt + A_TS, 8);
	memcpy(b + 12, pkt + A_EE, 2);
	memcpy(b + 14, pkt + A_SSID, 2);
	if (refl) {
		memcpy(b + 16, pkt + A_RX, 8);
		memcpy(b + 24, pkt + A_SSEQ, 4);
		memcpy(b + 28, pkt + A_STS, 8);
		memcpy(b + 36, pkt + A_SEE, 2);
		b[40] = pkt[A_TTL];
	}
	memmove(pkt + STAMP_UNAUTH_LEN, pkt + STAMP_AUTH_LEN, len -
	    STAMP_AUTH_LEN);
	memcpy(pkt, b, sizeof(b));
}

/*
 * The reverse: a packet of ulen octets (44 or more) of the
 * unauthenticated layout, in place (room for ulen + 68), into the
 * authenticated one, its MBZ and HMAC zero.
 */
void
stamp_auth_widen(uint8_t *pkt, size_t ulen, bool refl)
{
	uint8_t	b[STAMP_UNAUTH_LEN];

	memcpy(b, pkt, sizeof(b));
	memmove(pkt + STAMP_AUTH_LEN, pkt + STAMP_UNAUTH_LEN, ulen -
	    STAMP_UNAUTH_LEN);
	memset(pkt, 0, STAMP_AUTH_LEN);
	memcpy(pkt, b, 4);
	memcpy(pkt + A_TS, b + 4, 8);
	memcpy(pkt + A_EE, b + 12, 2);
	memcpy(pkt + A_SSID, b + 14, 2);
	if (refl) {
		memcpy(pkt + A_RX, b + 16, 8);
		memcpy(pkt + A_SSEQ, b + 24, 4);
		memcpy(pkt + A_STS, b + 28, 8);
		memcpy(pkt + A_SEE, b + 36, 2);
		pkt[A_TTL] = b[40];
	}
}

/* The Timestamp of a reflected packet of the authenticated layout, in
 * the format its Error Estimate says. */
void
stamp_auth_send_time(uint8_t *pkt, const struct timespec *t3)
{

	stamp_ts_put(pkt + A_TS, (uint16_t)(pkt[A_EE] << 8 | pkt[A_EE + 1]),
	    t3);
}

/*
 * Where the HMAC TLV (RFC 8972 4.8) of a packet of len octets is, its
 * TLVs from base.  Fail closed: whatever follows the base must be
 * well-formed TLVs to its very end, each header whole, no length past
 * the packet, none of type 0 (stamp_tlv_next()'s walk, which the cores
 * take, stopping where this one does).  1 and its offset in *at when
 * there is an HMAC TLV where it must be (after every TLV but Extra
 * Padding, 16 octets long); 0 when nothing follows the base, or Extra
 * Padding TLVs alone, which protect nothing; -1 when the TLVs are
 * well-formed and there is no such HMAC TLV (missing, misplaced, of
 * another length); -2 when what follows the base is not well-formed
 * TLVs (trailing octets, a header cut short, a length overlong, a TLV
 * of type 0).
 */
static int
hmac_tlv(const uint8_t *pkt, size_t len, size_t base, size_t *at)
{
	struct stamp_tlv	v;
	size_t			off = base, here;
	bool			other = false, bad = false;
	int			rc;

	*at = 0;
	for (;;) {
		here = off;
		if (off >= len)
			break;
		if (len - off < STAMP_TLV_HDR)
			return (-2);
		v.type = pkt[off + 1];
		v.len = (uint16_t)(pkt[off + 2] << 8 | pkt[off + 3]);
		if (len - off - STAMP_TLV_HDR < v.len || v.type == 0)
			return (-2);
		off += STAMP_TLV_HDR + v.len;
		if (*at == 0 && v.type == STAMP_TLV_HMAC) {
			*at = here;
			if (v.len != STAMP_HMAC_LEN)
				bad = true;
		} else if (*at == 0 && v.type != STAMP_TLV_PAD)
			other = true;
		else if (*at != 0 && v.type != STAMP_TLV_PAD)
			bad = true;
	}
	if (*at == 0)
		rc = other ? -1 : 0;
	else
		rc = bad ? -1 : 1;
	return (rc);
}

/*
 * The TLVs of a packet of len octets, from base, checked under k: 1
 * when its HMAC TLV is right, or nothing follows the base but Extra
 * Padding TLVs (or nothing at all); 0 when the TLVs are well-formed
 * but their HMAC TLV is wrong, missing or out of its place (a reflector
 * flags them I, RFC 8972 4.8); -1 when what follows the base is not
 * well-formed TLVs to its end: nothing of it may be trusted, nor
 * flagged.
 */
int
stamp_auth_tlv_verify(const struct stamp_key *k, const uint8_t *pkt,
    size_t len, size_t base)
{
	uint8_t	h[STAMP_HMAC_LEN];
	size_t	at;
	int	rc;
	bool	ok;

	if ((rc = hmac_tlv(pkt, len, base, &at)) == -2)
		return (-1);
	if (rc != 1)
		return (rc == 0 ? 1 : 0);
	if (stamp_hmac(k, pkt, 4, pkt + base, at - base, h) == -1)
		return (0);
	ok = CRYPTO_memcmp(h, pkt + at + STAMP_TLV_HDR, STAMP_HMAC_LEN) == 0;
	OPENSSL_cleanse(h, sizeof(h));
	return (ok ? 1 : 0);
}

/* The HMAC TLV of a packet, if it has one, made under k: 0, or -1. */
int
stamp_auth_tlv_seal(const struct stamp_key *k, uint8_t *pkt, size_t len,
    size_t base)
{
	size_t	at;

	if (hmac_tlv(pkt, len, base, &at) != 1)
		return (0);
	return (stamp_hmac(k, pkt, 4, pkt + base, at - base, pkt + at +
	    STAMP_TLV_HDR));
}

/* ---- Keys ------------------------------------------------------- */

void
stamp_keys_free(struct stamp_key *keys, size_t n)
{

	if (keys == NULL)
		return;
	explicit_bzero(keys, n * sizeof(*keys));
	free(keys);
}

static int
hexval(int c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	c = tolower(c);
	return (c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1);
}

/*
 * Keys from text (len octets): a line each, "ssid key", the SSID 0 to
 * 65535 or "*" for any, the key 32 to 128 hexadecimal digits (16 to 64
 * octets); "#" a comment.  0 and the keys in *keysp (*np of them), or
 * -1 and why in why (a line's number, never a key).
 */
int
stamp_keys_parse(const char *text, size_t len, struct stamp_key **keysp,
    size_t *np, char *why, size_t whylen)
{
	struct stamp_key	*keys = NULL, *nk;
	const char		*p = text, *end = text + len, *eol, *w, *e;
	size_t			 n = 0, cap = 0, i, wl;
	long			 ssid;
	int			 line = 0, hi, lo;
	char			 num[8];

	*keysp = NULL;
	*np = 0;
	for (; p < end; p = eol + (eol < end)) {
		line++;
		if ((eol = memchr(p, '\n', (size_t)(end - p))) == NULL)
			eol = end;
		if ((e = memchr(p, '#', (size_t)(eol - p))) == NULL)
			e = eol;
		while (p < e && isspace((unsigned char)*p))
			p++;
		if (p == e)
			continue;
		/* The SSID. */
		for (w = p; p < e && !isspace((unsigned char)*p); p++)
			;
		wl = (size_t)(p - w);
		if (wl == 1 && *w == '*')
			ssid = STAMP_SSID_ANY;
		else {
			char	*x;

			if (wl == 0 || wl >= sizeof(num))
				goto bad;
			memcpy(num, w, wl);
			num[wl] = '\0';
			errno = 0;
			ssid = strtol(num, &x, 10);
			if (errno != 0 || *x != '\0' || !isdigit((unsigned char)
			    num[0]) || ssid < 0 || ssid > 65535)
				goto bad;
		}
		while (p < e && isspace((unsigned char)*p))
			p++;
		/* The key. */
		for (w = p; p < e && !isspace((unsigned char)*p); p++)
			;
		wl = (size_t)(p - w);
		while (p < e && isspace((unsigned char)*p))
			p++;
		if (p != e || wl % 2 != 0 || wl < 2 * STAMP_KEY_MIN || wl > 2 *
		    STAMP_KEY_MAX)
			goto bad;
		if (n == STAMP_KEYS_MAX) {
			(void)snprintf(why, whylen, "line %d: more than %d keys",
			    line, STAMP_KEYS_MAX);
			stamp_keys_free(keys, cap);
			return (-1);
		}
		if (n == cap) {
			size_t	ncap = cap == 0 ? 8 : cap * 2;

			if ((nk = calloc(ncap, sizeof(*nk))) == NULL) {
				(void)snprintf(why, whylen, "%s", strerror(errno));
				stamp_keys_free(keys, cap);
				return (-1);
			}
			if (keys != NULL)
				memcpy(nk, keys, n * sizeof(*nk));
			stamp_keys_free(keys, cap);
			keys = nk;
			cap = ncap;
		}
		keys[n].ssid = (int32_t)ssid;
		keys[n].len = wl / 2;
		for (i = 0; i < wl / 2; i++) {
			if ((hi = hexval((unsigned char)w[2 * i])) < 0 ||
			    (lo = hexval((unsigned char)w[2 * i + 1])) < 0) {
				explicit_bzero(&keys[n], sizeof(keys[n]));
				goto bad;
			}
			keys[n].key[i] = (uint8_t)(hi << 4 | lo);
		}
		n++;
	}
	if (n == 0) {
		free(keys);
		keys = NULL;
	} else if (n < cap) {
		/* As many as there are: the rest zero, freed. */
		if ((nk = calloc(n, sizeof(*nk))) != NULL) {
			memcpy(nk, keys, n * sizeof(*nk));
			stamp_keys_free(keys, cap);
			keys = nk;
		}
	}
	*keysp = keys;
	*np = n;
	return (0);
bad:
	(void)snprintf(why, whylen, "line %d is not \"ssid key\": an SSID 0 to "
	    "65535 or *, and %d to %d hexadecimal digits", line, 2 *
	    STAMP_KEY_MIN, 2 * STAMP_KEY_MAX);
	stamp_keys_free(keys, cap);
	return (-1);
}

/*
 * The keys of an open file (stamp_keys_parse()), read from its start:
 * a regular file its owner alone may read or write (no group or other
 * bits), owned by root or by this process's user.  0, or -1 and why.
 */
int
stamp_keys_read(int fd, struct stamp_key **keysp, size_t *np, char *why,
    size_t whylen)
{
	struct stat	 st;
	char		*buf;
	size_t		 got = 0;
	ssize_t		 r;
	int		 rc;

	*keysp = NULL;
	*np = 0;
	if (fstat(fd, &st) == -1) {
		(void)snprintf(why, whylen, "%s", strerror(errno));
		return (-1);
	}
	if (!S_ISREG(st.st_mode)) {
		(void)snprintf(why, whylen, "not a regular file");
		return (-1);
	}
	if ((st.st_mode & 077) != 0) {
		(void)snprintf(why, whylen, "mode %04o: others may read it (0600 "
		    "at most)", (unsigned)(st.st_mode & 07777));
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != geteuid()) {
		(void)snprintf(why, whylen, "owned by uid %ju, not root",
		    (uintmax_t)st.st_uid);
		return (-1);
	}
	if (st.st_size > KEYFILE_MAX) {
		(void)snprintf(why, whylen, "larger than %d octets",
		    KEYFILE_MAX);
		return (-1);
	}
	if ((buf = malloc((size_t)st.st_size + 1)) == NULL) {
		(void)snprintf(why, whylen, "%s", strerror(errno));
		return (-1);
	}
	while (got < (size_t)st.st_size && (r = pread(fd, buf + got,
	    (size_t)st.st_size - got, (off_t)got)) > 0)
		got += (size_t)r;
	rc = stamp_keys_parse(buf, got, keysp, np, why, whylen);
	explicit_bzero(buf, (size_t)st.st_size + 1);
	free(buf);
	return (rc);
}
