/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The UDP socket of either end.  The time a packet came in is the
 * kernel's (SO_TIMESTAMP with SO_TS_CLOCK SO_TS_REALTIME, an
 * SCM_REALTIME timespec; a sender's SO_TS_MONOTONIC, SCM_MONOTONIC),
 * the TTL or Hop Limit it came with is said
 * (IP_RECVTTL, IPV6_RECVHOPLIMIT), and the address it came to
 * (IP_RECVDSTADDR, IPV6_RECVPKTINFO), so that a reply leaves from it
 * (IP_SENDSRCADDR, IPV6_PKTINFO).  The socket's FIB is the process's,
 * as setfib(1) or setfib(2) set it, or the one SO_SETFIB says.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "stamp.h"

/* A UDP socket of family af bound to port (0: any) on every address,
 * non-blocking, in the process's FIB; -1 with errno. */
int
stamp_socket(int af, uint16_t port, int flags)
{

	return (stamp_socket_fib(af, port, flags, -1));
}

/* The same in FIB fib (SO_SETFIB, before it is bound), -1 the
 * process's.  STAMP_SOCK_MONOTONIC: the kernel's receive time on the
 * monotonic clock (a sender's round trip), else the time of day. */
int
stamp_socket_fib(int af, uint16_t port, int flags, int fib)
{
	struct sockaddr_storage	ss;
	int			fd, on = 1, v, e;

	if ((fd = socket(af, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) ==
	    -1)
		return (-1);
	if (fib >= 0 && setsockopt(fd, SOL_SOCKET, SO_SETFIB, &fib,
	    sizeof(fib)) == -1) {
		e = errno;
		close(fd);
		errno = e;
		return (-1);
	}
	v = flags & STAMP_SOCK_MONOTONIC ? SO_TS_MONOTONIC : SO_TS_REALTIME;
	(void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on));
	(void)setsockopt(fd, SOL_SOCKET, SO_TS_CLOCK, &v, sizeof(v));
	memset(&ss, 0, sizeof(ss));
	v = 255;
	if (af == AF_INET) {
		struct sockaddr_in	*s4 = (struct sockaddr_in *)(void *)&ss;

		(void)setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
		(void)setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &on,
		    sizeof(on));
		if (flags & STAMP_SOCK_REFLECTOR)
			(void)setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
		s4->sin_family = AF_INET;
		s4->sin_len = sizeof(*s4);
		s4->sin_port = htons(port);
	} else if (af == AF_INET6) {
		struct sockaddr_in6	*s6 = (struct sockaddr_in6 *)(void *)&ss;

		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on,
		    sizeof(on));
		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on,
		    sizeof(on));
		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		    sizeof(on));
		if (flags & STAMP_SOCK_REFLECTOR)
			(void)setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			    &v, sizeof(v));
		s6->sin6_family = AF_INET6;
		s6->sin6_len = sizeof(*s6);
		s6->sin6_port = htons(port);
	} else {
		close(fd);
		errno = EAFNOSUPPORT;
		return (-1);
	}
	if (bind(fd, (struct sockaddr *)&ss, ss.ss_len) == -1) {
		e = errno;
		close(fd);
		errno = e;
		return (-1);
	}
	return (fd);
}

/* A packet read into buf, what came with it in ri: its length, or -1
 * with errno (EAGAIN: none). */
ssize_t
stamp_recv(int fd, uint8_t *buf, size_t len, struct stamp_rxinfo *ri)
{
	struct msghdr	 msg;
	struct iovec	 iov;
	struct cmsghdr	*cm;
	union {
		struct cmsghdr	hdr;
		char		buf[256];
	}		 cin;
	ssize_t		 n;
	bool		 have_t = false, have_m = false;

	memset(ri, 0, sizeof(*ri));
	ri->ttl = -1;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buf;
	iov.iov_len = len;
	msg.msg_name = &ri->peer;
	msg.msg_namelen = sizeof(ri->peer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cin.buf;
	msg.msg_controllen = sizeof(cin.buf);
	if ((n = recvmsg(fd, &msg, 0)) == -1)
		return (-1);
	ri->trunc = (msg.msg_flags & MSG_TRUNC) != 0;
	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg,
	    cm)) {
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type ==
		    SCM_REALTIME && cm->cmsg_len >=
		    CMSG_LEN(sizeof(struct timespec))) {
			memcpy(&ri->t, CMSG_DATA(cm), sizeof(ri->t));
			have_t = true;
		} else if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type ==
		    SCM_MONOTONIC && cm->cmsg_len >=
		    CMSG_LEN(sizeof(struct timespec))) {
			memcpy(&ri->mono, CMSG_DATA(cm), sizeof(ri->mono));
			have_m = true;
		} else if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type ==
		    SCM_TIMESTAMP && cm->cmsg_len >=
		    CMSG_LEN(sizeof(struct timeval))) {
			struct timeval	tv;

			memcpy(&tv, CMSG_DATA(cm), sizeof(tv));
			TIMEVAL_TO_TIMESPEC(&tv, &ri->t);
			have_t = true;
		} else if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type ==
		    IP_RECVTTL && cm->cmsg_len >= CMSG_LEN(1)) {
			ri->ttl = *(uint8_t *)CMSG_DATA(cm);
		} else if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type ==
		    IP_RECVDSTADDR && cm->cmsg_len >=
		    CMSG_LEN(sizeof(struct in_addr))) {
			struct sockaddr_in	*s4 = (struct sockaddr_in *)
			    (void *)&ri->local;

			s4->sin_family = AF_INET;
			s4->sin_len = sizeof(*s4);
			memcpy(&s4->sin_addr, CMSG_DATA(cm),
			    sizeof(s4->sin_addr));
		} else if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type ==
		    IPV6_HOPLIMIT && cm->cmsg_len >= CMSG_LEN(sizeof(int))) {
			memcpy(&ri->ttl, CMSG_DATA(cm), sizeof(int));
		} else if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type ==
		    IPV6_PKTINFO && cm->cmsg_len >=
		    CMSG_LEN(sizeof(struct in6_pktinfo))) {
			struct sockaddr_in6	*s6 = (struct sockaddr_in6 *)
			    (void *)&ri->local;
			struct in6_pktinfo	 pi6;

			memcpy(&pi6, CMSG_DATA(cm), sizeof(pi6));
			s6->sin6_family = AF_INET6;
			s6->sin6_len = sizeof(*s6);
			s6->sin6_addr = pi6.ipi6_addr;
			ri->ifindex = pi6.ipi6_ifindex;
			if (IN6_IS_ADDR_LINKLOCAL(&pi6.ipi6_addr))
				s6->sin6_scope_id = pi6.ipi6_ifindex;
		}
	}
	if (!have_t)
		clock_gettime(CLOCK_REALTIME, &ri->t);
	if (!have_m)
		clock_gettime(CLOCK_MONOTONIC, &ri->mono);
	return (n);
}

/*
 * buf sent to to, from the address from (NULL or of no family: the one
 * the routes choose) on interface ifindex (IPv6; 0 any).  The address
 * it came to not being of an interface of the socket's FIB (the
 * loopback's, in a FIB but 0), from the one the table chooses.  0, or
 * -1 with errno.
 */
int
stamp_send(int fd, const uint8_t *buf, size_t len, const struct sockaddr *to,
    const struct sockaddr *from, unsigned ifindex)
{
	struct msghdr	 msg;
	struct iovec	 iov;
	struct cmsghdr	*cm;
	union {
		struct cmsghdr	hdr;
		char		buf[128];
	}		 cout;

	memset(&msg, 0, sizeof(msg));
	memset(&cout, 0, sizeof(cout));
	iov.iov_base = (void *)(uintptr_t)buf;
	iov.iov_len = len;
	msg.msg_name = (void *)(uintptr_t)to;
	msg.msg_namelen = to->sa_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (from != NULL && from->sa_family == AF_INET && to->sa_family ==
	    AF_INET) {
		msg.msg_control = cout.buf;
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
		cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = IPPROTO_IP;
		cm->cmsg_type = IP_SENDSRCADDR;
		cm->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
		memcpy(CMSG_DATA(cm), &((const struct sockaddr_in *)
		    (const void *)from)->sin_addr, sizeof(struct in_addr));
	} else if (from != NULL && from->sa_family == AF_INET6 &&
	    to->sa_family == AF_INET6) {
		struct in6_pktinfo	pi6;

		memset(&pi6, 0, sizeof(pi6));
		pi6.ipi6_addr = ((const struct sockaddr_in6 *)
		    (const void *)from)->sin6_addr;
		pi6.ipi6_ifindex = ifindex;
		msg.msg_control = cout.buf;
		msg.msg_controllen = CMSG_SPACE(sizeof(pi6));
		cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = IPPROTO_IPV6;
		cm->cmsg_type = IPV6_PKTINFO;
		cm->cmsg_len = CMSG_LEN(sizeof(pi6));
		memcpy(CMSG_DATA(cm), &pi6, sizeof(pi6));
	}
	if (sendmsg(fd, &msg, 0) != -1)
		return (0);
	if (errno != EADDRNOTAVAIL || msg.msg_controllen == 0)
		return (-1);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	return (sendmsg(fd, &msg, 0) == -1 ? -1 : 0);
}

/* host (an address or a name) and port into ss: 0, or -1 with errno
 * EADDRNOTAVAIL. */
int
stamp_sockaddr(const char *host, uint16_t port, struct sockaddr_storage *ss)
{
	struct addrinfo	 hints, *res;
	char		 serv[8];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICSERV;
	(void)snprintf(serv, sizeof(serv), "%u", port);
	if (getaddrinfo(host, serv, &hints, &res) != 0 || res == NULL) {
		errno = EADDRNOTAVAIL;
		return (-1);
	}
	memset(ss, 0, sizeof(*ss));
	memcpy(ss, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return (0);
}

uint16_t
stamp_sa_port(const struct sockaddr *sa)
{

	if (sa->sa_family == AF_INET)
		return (ntohs(((const struct sockaddr_in *)(const void *)sa)->
		    sin_port));
	if (sa->sa_family == AF_INET6)
		return (ntohs(((const struct sockaddr_in6 *)(const void *)sa)->
		    sin6_port));
	return (0);
}

const char *
stamp_sa_ntop(const struct sockaddr *sa, char *buf, size_t len)
{
	const void	*a;

	if (sa->sa_family == AF_INET)
		a = &((const struct sockaddr_in *)(const void *)sa)->sin_addr;
	else if (sa->sa_family == AF_INET6)
		a = &((const struct sockaddr_in6 *)(const void *)sa)->sin6_addr;
	else {
		(void)snprintf(buf, len, "?");
		return (buf);
	}
	if (inet_ntop(sa->sa_family, a, buf, (socklen_t)len) == NULL)
		(void)snprintf(buf, len, "?");
	return (buf);
}
