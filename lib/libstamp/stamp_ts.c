/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Timestamps and the Error Estimate.  NTP's 64-bit format (RFC 5905
 * 6): seconds since 1900 and a binary fraction, its era told by the
 * top bit as RFC 4330 3 does (0 from 2036); PTPv2's truncated format
 * (RFC 8762 4.2.1): seconds and nanoseconds, of whatever epoch the
 * caller's timespec has.  The Error Estimate (RFC 4656 4.1.2): S, Z,
 * an 6-bit Scale and an 8-bit Multiplier, the error Multiplier *
 * 2^(Scale - 32) seconds.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/timex.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "stamp.h"

#define	NTP_UNIX	2208988800ULL	/* 1900 to 1970, in seconds */

static void
put32(uint8_t *p, uint32_t v)
{

	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t
get32(const uint8_t *p)
{

	return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | p[3]);
}

void
stamp_ntp_put(uint8_t *p, const struct timespec *ts)
{

	put32(p, (uint32_t)((uint64_t)ts->tv_sec + NTP_UNIX));
	put32(p + 4, (uint32_t)(((uint64_t)ts->tv_nsec << 32) / 1000000000));
}

void
stamp_ntp_get(const uint8_t *p, struct timespec *ts)
{
	uint64_t	s = get32(p), f = get32(p + 4);

	/* Era 1 (from 2036) when the top bit is clear. */
	if ((s & 0x80000000U) == 0)
		s += 1ULL << 32;
	ts->tv_sec = (time_t)(s - NTP_UNIX);
	ts->tv_nsec = (long)((f * 1000000000 + (1ULL << 31)) >> 32);
	if (ts->tv_nsec >= 1000000000) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000;
	}
}

void
stamp_ptp_put(uint8_t *p, const struct timespec *ts)
{

	put32(p, (uint32_t)ts->tv_sec);
	put32(p + 4, (uint32_t)ts->tv_nsec);
}

void
stamp_ptp_get(const uint8_t *p, struct timespec *ts)
{

	ts->tv_sec = (time_t)get32(p);
	ts->tv_nsec = (long)(get32(p + 4) % 1000000000);
}

void
stamp_ts_put(uint8_t *p, uint16_t ee, const struct timespec *ts)
{

	if (ee & STAMP_EE_Z)
		stamp_ptp_put(p, ts);
	else
		stamp_ntp_put(p, ts);
}

void
stamp_ts_get(const uint8_t *p, uint16_t ee, struct timespec *ts)
{

	if (ee & STAMP_EE_Z)
		stamp_ptp_get(p, ts);
	else
		stamp_ntp_get(p, ts);
}

/* a - b, in seconds. */
double
stamp_ts_sub(const struct timespec *a, const struct timespec *b)
{

	return ((double)(a->tv_sec - b->tv_sec) +
	    (double)(a->tv_nsec - b->tv_nsec) / 1e9);
}

/* An Error Estimate of err seconds: the least scale whose multiplier
 * fits an octet, the multiplier rounded up, never 0. */
uint16_t
stamp_ee_make(bool synced, bool ptp, double err)
{
	uint64_t	m = 255;
	int		scale;

	if (err < 0)
		err = 0;
	for (scale = 0; scale < 64; scale++) {
		double	x = err * 4294967296.0 / (double)(1ULL << scale);

		if (x < 255) {
			m = (uint64_t)x + 1;
			break;
		}
	}
	if (scale == 64)
		scale = 63;
	if (m > 255)
		m = 255;
	return ((uint16_t)((synced ? STAMP_EE_S : 0) | (ptp ? STAMP_EE_Z :
	    0) | (scale << 8) | (int)m));
}

double
stamp_ee_seconds(uint16_t ee)
{
	int	scale = (ee >> 8) & 0x3f;

	return ((double)(ee & 0xff) * (double)(1ULL << scale) / 4294967296.0);
}

/* The clock's, from ntp_gettime(2): synchronised unless its state is
 * TIME_ERROR, the error its maxerror; NTP's format. */
uint16_t
stamp_ee_clock(void)
{
	struct ntptimeval	ntv;

	if (ntp_gettime(&ntv) == -1)
		return (stamp_ee_make(false, false, 16.0));
	return (stamp_ee_make(ntv.time_state != TIME_ERROR, false,
	    (double)ntv.maxerror / 1e6));
}
