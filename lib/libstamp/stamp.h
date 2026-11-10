/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libstamp: the Simple Two-way Active Measurement Protocol (RFC 8762),
 * with the Session-Sender Identifier of RFC 8972.  The packets of the
 * unauthenticated mode, the timestamps (NTP's 64-bit format and PTPv2's
 * truncated one) and the Error Estimate of RFC 4656, the reflector's
 * core (its sessions, its rate limits, its reply), the sender's (its
 * sequence, the replies matched, the round trip and the loss each way)
 * and the UDP socket both ends use.  See libstamp(3).
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

int	stamp_tlv_next(const uint8_t *, size_t, size_t *, struct stamp_tlv *);

/* ---- The Session-Reflector -------------------------------------- */

struct stamp_refl_conf {
	bool		 stateful;	/* RFC 8762 4.3.2: a counter a session */
	double		 rate;		/* replies a second to a source; 0 any */
	double		 burst;		/* its bucket; 0: twice the rate */
	double		 rate_total;	/* to all of them; 0 any */
	unsigned	 sess_max;	/* 0: STAMP_SESS_MAX */
	unsigned	 sess_idle;	/* s; 0: STAMP_SESS_IDLE */
	uint16_t	 port;		/* its own: never answered */
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
};

/* A packet's outcome: its reply, or none within the timeout. */
struct stamp_sample {
	uint32_t		 seq;	/* the sender's */
	bool			 lost;
	double			 rtt;	/* s: (T4 - T1) - (T3 - T2) */
	double			 refl;	/* s: T3 - T2, the reflector's time */
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
	    double, struct stamp_sample *);
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
	struct timespec		 t;	/* the kernel's, else the clock's */
	struct timespec		 mono;	/* the same, monotonic */
	bool			 trunc;
};

int	stamp_socket(int, uint16_t, int);
int	stamp_socket_fib(int, uint16_t, int, int);
ssize_t	stamp_recv(int, uint8_t *, size_t, struct stamp_rxinfo *);
int	stamp_send(int, const uint8_t *, size_t, const struct sockaddr *,
	    const struct sockaddr *, unsigned);
int	stamp_sockaddr(const char *, uint16_t, struct sockaddr_storage *);
uint16_t stamp_sa_port(const struct sockaddr *);
const char *stamp_sa_ntop(const struct sockaddr *, char *, size_t);

#endif /* !_STAMP_H_ */
