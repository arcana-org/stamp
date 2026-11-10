/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * udplossy: a UDP relay on the loopback that loses packets on purpose,
 * and delays them, for stampd_test.  What comes to port lport is sent
 * on to port rport, the replies back to whoever sent last; every f-th
 * packet on the way out and every b-th reply on the way back is
 * dropped (0: none), so that a sender's loss each way is known
 * exactly; the packets on the way out are held delay milliseconds
 * (default 0), the replies none, so that the delay is one way alone.
 * "ready" on the standard output once it listens; it runs until
 * killed.
 *
 *	udplossy lport rport f b [delay]
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	HELD	256

static struct {
	double	 due;
	size_t	 len;
	char	 buf[9000];
} held[HELD];
static unsigned	 h_head, h_n;

static struct sockaddr_in
lo(int port)
{
	struct sockaddr_in	s;

	memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_len = sizeof(s);
	s.sin_port = htons((uint16_t)port);
	s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return (s);
}

static double
mono(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in	 a, r, peer;
	struct pollfd		 pfd[2];
	socklen_t		 plen;
	unsigned long		 fwd = 0, back = 0, f, b;
	char			 buf[9000];
	double			 delay = 0, now;
	ssize_t			 n;
	int			 in, out, wait;
	bool			 have = false;

	if (argc != 5 && argc != 6)
		errx(1, "usage: udplossy lport rport f b [delay]");
	a = lo(atoi(argv[1]));
	r = lo(atoi(argv[2]));
	f = strtoul(argv[3], NULL, 10);
	b = strtoul(argv[4], NULL, 10);
	if (argc == 6)
		delay = strtod(argv[5], NULL) / 1000;
	if ((in = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ||
	    (out = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	if (bind(in, (struct sockaddr *)&a, sizeof(a)) == -1)
		err(1, "bind");
	if (connect(out, (struct sockaddr *)&r, sizeof(r)) == -1)
		err(1, "connect");
	printf("ready\n");
	fflush(stdout);
	pfd[0].fd = in;
	pfd[1].fd = out;
	pfd[0].events = pfd[1].events = POLLIN;
	for (;;) {
		/* Those held whose time has come, sent on. */
		now = mono();
		while (h_n > 0 && held[h_head].due <= now) {
			(void)send(out, held[h_head].buf, held[h_head].len, 0);
			h_head = (h_head + 1) % HELD;
			h_n--;
		}
		wait = h_n > 0 ? (int)((held[h_head].due - now) * 1000) + 1 :
		    -1;
		if (poll(pfd, 2, wait) == -1)
			err(1, "poll");
		if (pfd[0].revents & POLLIN) {
			plen = sizeof(peer);
			if ((n = recvfrom(in, buf, sizeof(buf), 0,
			    (struct sockaddr *)&peer, &plen)) > 0) {
				have = true;
				if (f != 0 && ++fwd % f == 0)
					;
				else if (delay <= 0)
					(void)send(out, buf, (size_t)n, 0);
				else if (h_n < HELD) {
					unsigned t = (h_head + h_n) % HELD;

					held[t].due = mono() + delay;
					held[t].len = (size_t)n;
					memcpy(held[t].buf, buf, (size_t)n);
					h_n++;
				}
			}
		}
		if (pfd[1].revents & POLLIN) {
			if ((n = recv(out, buf, sizeof(buf), 0)) > 0 && have &&
			    (b == 0 || ++back % b != 0))
				(void)sendto(in, buf, (size_t)n, 0,
				    (struct sockaddr *)&peer, sizeof(peer));
		}
	}
}
