/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * udplossy: a UDP relay on the loopback that loses packets on purpose,
 * for stampd_test.  What comes to port lport is sent on to port rport,
 * the replies back to whoever sent last; every f-th packet on the way
 * out and every b-th reply on the way back is dropped (0: none), so
 * that a sender's loss each way is known exactly.  "ready" on the
 * standard output once it listens; it runs until killed.
 *
 *	udplossy lport rport f b
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
#include <unistd.h>

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

int
main(int argc, char *argv[])
{
	struct sockaddr_in	 a, r, peer;
	struct pollfd		 pfd[2];
	socklen_t		 plen;
	unsigned long		 fwd = 0, back = 0, f, b;
	char			 buf[9000];
	ssize_t			 n;
	int			 in, out;
	bool			 have = false;

	if (argc != 5)
		errx(1, "usage: udplossy lport rport f b");
	a = lo(atoi(argv[1]));
	r = lo(atoi(argv[2]));
	f = strtoul(argv[3], NULL, 10);
	b = strtoul(argv[4], NULL, 10);
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
		if (poll(pfd, 2, -1) == -1)
			err(1, "poll");
		if (pfd[0].revents & POLLIN) {
			plen = sizeof(peer);
			if ((n = recvfrom(in, buf, sizeof(buf), 0,
			    (struct sockaddr *)&peer, &plen)) > 0) {
				have = true;
				if (f == 0 || ++fwd % f != 0)
					(void)send(out, buf, (size_t)n, 0);
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
