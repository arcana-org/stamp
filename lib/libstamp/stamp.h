/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libstamp: the Simple Two-way Active Measurement Protocol (RFC 8762),
 * with the Session-Sender Identifier and the Timestamp Information and
 * Class of Service TLVs of RFC 8972.  The packets of the unauthenticated mode, the timestamps
 * (NTP's 64-bit format and PTPv2's truncated one) and the Error
 * Estimate of RFC 4656, the clock's synchronisation, the reflector's
 * core (its sessions, its rate limits, its reply), the sender's (its
 * sequence, the replies matched, the round trip, the delay and the
 * loss each way) and the UDP socket both ends use.  See libstamp(3).
 */

#ifndef _STAMP_H_
#define	_STAMP_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define	STAMP_PORT		862	/* RFC 8762 section 4.1 */
#define	STAMP_UNAUTH_LEN	44	/* the base packet, both ways */
#define	STAMP_AUTH_LEN		112	/* authenticated mode's (not yet) */
#define	STAMP_PKT_MAX		9000	/* about a jumbo frame's payload */

/* The Error Estimate (RFC 4656 section 4.1.2). */
#define	STAMP_EE_S		0x8000	/* synchronised to UTC */
#define	STAMP_EE_Z		0x4000	/* the timestamps PTP's, else NTP's */

/* Packet modes: only the unauthenticated one is implemented. */
enum stamp_auth {
	STAMP_UNAUTH = 0,
	STAMP_AUTH = 1
};

/* ---- Timestamps ------------------------------------------------- */

void	stamp_ntp_put(uint8_t *, const struct timespec *);
void	stamp_ntp_get(const uint8_t *, struct timespec *);
void	stamp_ptp_put(uint8_t *, const struct timespec *);
void	stamp_ptp_get(const uint8_t *, struct timespec *);
/* A timestamp in the format the Error Estimate's Z bit says. */
void	stamp_ts_put(uint8_t *, uint16_t, const struct timespec *);
void	stamp_ts_get(const uint8_t *, uint16_t, struct timespec *);
double	stamp_ts_sub(const struct timespec *, const struct timespec *);

uint16_t stamp_ee_make(bool, bool, double);
double	stamp_ee_seconds(uint16_t);
uint16_t stamp_ee_clock(void);

/* Synchronisation sources (RFC 8972 4.3, IANA's registry). */
#define	STAMP_SYNC_NTP		1
#define	STAMP_SYNC_PTP		2
#define	STAMP_SYNC_SSU		3	/* SSU/BITS */
#define	STAMP_SYNC_GNSS		4	/* GPS, GLONASS, Galileo, ... */
#define	STAMP_SYNC_LOCAL	5	/* free-running */
/* Timestamping methods (the same). */
#define	STAMP_TSM_HW		1	/* hardware assisted */
#define	STAMP_TSM_SW		2	/* software, local */
#define	STAMP_TSM_CP		3	/* the control plane's */

/* The clock as this end tells it: its Error Estimate and what it is
 * synchronised by. */
struct stamp_clock {
	uint16_t	 ee;
	uint8_t		 sync;		/* STAMP_SYNC_* */
};

void	stamp_clock_get(struct stamp_clock *);
int	stamp_clock_set(const char *);
const char *stamp_sync_name(uint8_t);
const char *stamp_tsm_name(uint8_t);

/* ---- Packets (unauthenticated mode) ----------------------------- */

/* A Session-Sender test packet (RFC 8762 4.2.1, RFC 8972 3). */
struct stamp_test {
	uint32_t	 seq;
	struct timespec	 ts;
	uint16_t	 ee;
	uint16_t	 ssid;
};

/* A Session-Reflector test packet (RFC 8762 4.3.1, RFC 8972 3). */
struct stamp_reflected {
	uint32_t	 seq;
	struct timespec	 ts;		/* T3 */
	uint16_t	 ee;
	uint16_t	 ssid;
	struct timespec	 rx;		/* T2, the Receive Timestamp */
	uint32_t	 sseq;		/* the Session-Sender's */
	struct timespec	 sts;		/* T1, echoed */
	uint16_t	 see;
	uint8_t		 sttl;
	bool		 mbz_ok;	/* the MBZ octets were zero */
};

int	stamp_test_encode(uint8_t *, size_t, const struct stamp_test *);
int	stamp_test_decode(const uint8_t *, size_t, struct stamp_test *);
int	stamp_reflected_decode(const uint8_t *, size_t,
	    struct stamp_reflected *);

/* A TLV after the base packet (RFC 8972 section 4). */
struct stamp_tlv {
	uint8_t		 flags;
	uint8_t		 type;
	uint16_t	 len;
	const uint8_t	*value;
};
#define	STAMP_TLV_U		0x80	/* unrecognised */
#define	STAMP_TLV_M		0x40	/* malformed */
#define	STAMP_TLV_I		0x20	/* integrity failed */

/* TLV types (RFC 8972 4, IANA's registry). */
#define	STAMP_TLV_PAD		1	/* Extra Padding */
#define	STAMP_TLV_TSINFO	3	/* Timestamp Information */
#define	STAMP_TLV_COS		4	/* Class of Service */
#define	STAMP_TLV_HDR		4
#define	STAMP_TSINFO_LEN	8	/* the TLV, its header with it */
#define	STAMP_COS_LEN		8	/* the same */

/* The Timestamp Information TLV's value (RFC 8972 4.3): what the
 * reflector's clock is synchronised by and how it took T2 (in) and T3
 * (out). */
struct stamp_tsinfo {
	uint8_t		 sync_in, ts_in, sync_out, ts_out;
};

/* The Class of Service TLV's value (RFC 8972 4.4): the DSCP the sender
 * asks the reply to carry (dscp1), the DSCP and ECN the request reached
 * the reflector with (dscp2, ecn), and rp 1 when the reflector would
 * not set dscp1 (its reply carrying the DSCP the request came with). */
struct stamp_cos {
	uint8_t		 dscp1, dscp2, ecn, rp;
};

int	stamp_tlv_next(const uint8_t *, size_t, size_t *, struct stamp_tlv *);
int	stamp_tlv_put(uint8_t *, size_t, size_t *, uint8_t, const void *,
	    uint16_t);
int	stamp_tsinfo_find(const uint8_t *, size_t, struct stamp_tsinfo *);
int	stamp_cos_find(const uint8_t *, size_t, struct stamp_cos *);

/* ---- The Session-Reflector -------------------------------------- */

struct stamp_refl_conf {
	bool		 stateful;	/* RFC 8762 4.3.2: a counter a session */
	double		 rate;		/* replies a second to a source; 0 any */
	double		 burst;		/* its bucket; 0: twice the rate */
	double		 rate_total;	/* to all of them; 0 any */
	unsigned	 sess_max;	/* 0: STAMP_SESS_MAX */
	unsigned	 sess_idle;	/* s; 0: STAMP_SESS_IDLE */
	uint16_t	 port;		/* its own: never answered */
	uint8_t		 ts_out;	/* how T3 is taken; 0: STAMP_TSM_SW */
	/* The DSCPs a Class of Service TLV may not ask the reply to
	 * carry (bit n for DSCP n): their replies carry the request's
	 * DSCP, the TLV's RP 1. */
	uint64_t	 dscp_deny;
};
#define	STAMP_SESS_MAX		4096
#define	STAMP_SESS_IDLE		300

/* A packet as it came in. */
struct stamp_rx {
	const uint8_t		*pkt;
	size_t			 len;
	const struct sockaddr	*peer;	/* address and port */
	const struct sockaddr	*local;	/* the address it came to; NULL */
	int			 ttl;	/* -1 unknown */
	struct timespec		 t2;
	int			 tag;	/* of the session's key: a FIB */
	double			 mono;	/* monotonic seconds; 0 now */
	uint8_t			 ts_in;	/* how t2 was; 0: STAMP_TSM_SW */
	int			 tos;	/* the TOS or traffic class octet;
					   -1 unknown */
};

/* Why a packet was not answered. */
enum stamp_drop {
	STAMP_ANSWERED = 0,
	STAMP_DROP_SHORT,		/* under the base packet */
	STAMP_DROP_PORT,		/* from port 0 or the reflector's */
	STAMP_DROP_RATE,		/* over a rate limit */
	STAMP_DROP_NOMEM
};

struct stamp_refl_stats {
	uint64_t	 answered;
	uint64_t	 dropped[5];	/* by enum stamp_drop */
	size_t		 sessions;
};

struct stamp_refl;

struct stamp_refl *stamp_refl_new(const struct stamp_refl_conf *);
int	stamp_refl_setconf(struct stamp_refl *, const struct stamp_refl_conf *);
void	stamp_refl_free(struct stamp_refl *);
ssize_t	stamp_refl_reply(struct stamp_refl *, const struct stamp_rx *,
	    uint8_t *, size_t, enum stamp_drop *);
int	stamp_refl_reply_tos(const struct stamp_refl *);
void	stamp_refl_send_time(uint8_t *, const struct timespec *);
void	stamp_refl_expire(struct stamp_refl *, double);
void	stamp_refl_stats(const struct stamp_refl *, struct stamp_refl_stats *);
double	stamp_mono(void);

/* ---- The Session-Sender ----------------------------------------- */

/* What a reflector does with the Sequence Number (RFC 8762 4.3). */
enum stamp_mode {
	STAMP_MODE_UNKNOWN = 0,		/* told by the first reply */
	STAMP_MODE_STATELESS,		/* the sender's copied */
	STAMP_MODE_STATEFUL		/* its own counter, a session */
};

struct stamp_sender_conf {
	uint16_t	 ssid;
	bool		 seq_set;	/* seq0 as given; else random */
	uint32_t	 seq0;
	enum stamp_mode	 mode;		/* the reflector's, if known */
	double		 timeout;	/* s a reply is waited; 0: 2 */
	unsigned	 window;	/* in flight at most; 0: 256 */
	bool		 tsinfo;	/* the Timestamp Information TLV */
	bool		 cos;		/* the Class of Service TLV, asking */
	uint8_t		 dscp;		/* the reply to carry this DSCP */
	double		 owd_frac;	/* one way: both errors to half the
					   round trip at most; 0: 0.1 */
};
#define	STAMP_OWD_FRAC		0.1

/* A packet's outcome: its reply, or none within the timeout. */
struct stamp_sample {
	uint32_t		 seq;	/* the sender's */
	bool			 lost;
	double			 rtt;	/* s: (T4 - T1) - (T3 - T2) */
	double			 refl;	/* s: T3 - T2, the reflector's time */
	/* The delay each way: T2 - T1 and T4 - T3 when both clocks say
	 * they are synchronised and their errors together are within
	 * owd_frac of half the round trip (owd); else half the round
	 * trip each, an estimate. */
	double			 fwd, back;	/* s */
	bool			 owd;
	double			 err;	/* s: both Error Estimates' */
	bool			 has_tsinfo;	/* the reflector filled it */
	struct stamp_tsinfo	 tsinfo;
	bool			 has_cos;	/* the same */
	struct stamp_cos	 cos;
	struct stamp_reflected	 r;	/* the reply, when not lost */
};

struct stamp_sender_stats {
	uint64_t	 sent, received;
	uint64_t	 lost;		/* not back within the timeout */
	/* Of the lost, told apart by a stateful reflector's counter: */
	uint64_t	 fwd_lost;	/* never reached the reflector */
	uint64_t	 back_lost;	/* reflected, the reply not back */
	uint64_t	 unknown_lost;	/* a stateless one's, or not known */
	uint64_t	 late;		/* a reply after its timeout, or again */
	uint64_t	 foreign;	/* another SSID's, or no packet of ours */
	enum stamp_mode	 mode;
};

struct stamp_sender;

struct stamp_sender *stamp_sender_new(const struct stamp_sender_conf *);
void	stamp_sender_free(struct stamp_sender *);
int	stamp_sender_packet(struct stamp_sender *, uint8_t *, size_t,
	    const struct timespec *, double, struct stamp_sample *);
int	stamp_sender_reply(struct stamp_sender *, const uint8_t *, size_t,
	    double, const struct timespec *, struct stamp_sample *);
size_t	stamp_sender_len(const struct stamp_sender *, size_t);
int	stamp_sender_expire(struct stamp_sender *, double,
	    struct stamp_sample *);
double	stamp_sender_next(const struct stamp_sender *);
void	stamp_sender_stats(const struct stamp_sender *,
	    struct stamp_sender_stats *);
const char *stamp_mode_name(enum stamp_mode);

/* ---- Sockets ---------------------------------------------------- */

#define	STAMP_SOCK_REFLECTOR	0x01	/* TTL 255, the reply's */
#define	STAMP_SOCK_MONOTONIC	0x02	/* the kernel's time monotonic */

/* What came with a packet. */
struct stamp_rxinfo {
	struct sockaddr_storage	 peer;
	struct sockaddr_storage	 local;	/* ss_family 0: not said */
	unsigned		 ifindex;
	int			 ttl;	/* -1 not said */
	int			 tos;	/* TOS or traffic class; -1 not said */
	struct timespec		 t;	/* the kernel's, else the clock's */
	struct timespec		 mono;	/* the same, monotonic */
	bool			 hwts;	/* the kernel's by the hardware */
	bool			 trunc;
};

int	stamp_socket(int, uint16_t, int);
int	stamp_socket_fib(int, uint16_t, int, int);
ssize_t	stamp_recv(int, uint8_t *, size_t, struct stamp_rxinfo *);
int	stamp_send(int, const uint8_t *, size_t, const struct sockaddr *,
	    const struct sockaddr *, unsigned, int);
int	stamp_sockaddr(const char *, uint16_t, struct sockaddr_storage *);
uint16_t stamp_sa_port(const struct sockaddr *);
const char *stamp_sa_ntop(const struct sockaddr *, char *, size_t);

#endif /* !_STAMP_H_ */
