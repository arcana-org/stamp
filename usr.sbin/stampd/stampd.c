/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * stampd: a STAMP Session-Reflector (RFC 8762, RFC 8972's SSID), on
 * UDP 862 (-p) of every address, IPv4 and IPv6, in the FIB it is
 * started in: setfib(1), or rc.subr(8)'s stampd_fib, one stampd a FIB
 * (the rc script starts one for each of stampd_fibs).  Bound, it
 * writes its pidfile, then, run by root, gives up root: chroot(2) to
 * /var/empty, the user's (-u, _stampd) groups and ids.  SIGHUP reads
 * the configuration file again (-f); what the command line said stays.
 * The packets are libstamp's (stamp_refl_reply()): see stampd(8).
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <libutil.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "stamp.h"

#ifndef PATH_STAMPD_CONF
#define	PATH_STAMPD_CONF	"/usr/local/etc/stampd.conf"
#endif
#define	STAMPD_USER		"_stampd"
#define	PATH_EMPTY		"/var/empty"
#define	TICK_S			5	/* sessions ended, drops told */
#define	BURST			64	/* packets read from a socket a wakeup */

/* What the command line set, kept over the file's on a reload. */
#define	SET_MODE		0x01
#define	SET_RATE		0x02
#define	SET_TOTAL		0x04
#define	SET_DSCP		0x08

static struct stamp_refl_conf	 cl;	/* the command line's */
static int			 cl_set;
static struct stamp_refl	*refl;
static struct stamp_refl_conf	 cur;
static int			 fib;
static int			 conf_dir = -1;	/* the file's, kept for a reload */
static char			 conf_name[MAXPATHLEN];
static bool			 conf_must;	/* -f: it must be there */
static uint64_t			 drops_told;

static void
usage(void)
{

	fprintf(stderr, "usage: stampd [-d] [-C source[:error]] [-D dscps] "
	    "[-f file]\n"
	    "              [-m stateless | stateful] [-P pidfile] [-p port]\n"
	    "              [-r rate[/burst]] [-R rate] [-u user]\n");
	exit(1);
}

/* rate[/burst] into c; false when it is not one. */
static bool
parse_rate(const char *s, struct stamp_refl_conf *c)
{
	char		 buf[64], *slash;
	const char	*e;
	long long	 r, b;

	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return (false);
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	r = strtonum(buf, 0, 1000000, &e);
	if (e != NULL)
		return (false);
	b = 0;
	if (slash != NULL && ((b = strtonum(slash, 1, 1000000, &e)) == 0 ||
	    e != NULL))
		return (false);
	c->rate = (double)r;
	c->burst = (double)b;
	return (true);
}

static bool
parse_total(const char *s, struct stamp_refl_conf *c)
{
	const char	*e;
	long long	 r;

	r = strtonum(s, 0, 10000000, &e);
	if (e != NULL)
		return (false);
	c->rate_total = (double)r;
	return (true);
}

static bool
parse_location(const char *s, struct stamp_refl_conf *c)
{

	if (strcmp(s, "show") == 0)
		c->loc_hide = false;
	else if (strcmp(s, "hide") == 0)
		c->loc_hide = true;
	else
		return (false);
	return (true);
}

static bool
parse_mode(const char *s, struct stamp_refl_conf *c)
{

	if (strcmp(s, "stateful") == 0)
		c->stateful = true;
	else if (strcmp(s, "stateless") == 0)
		c->stateful = false;
	else
		return (false);
	return (true);
}

/* The DSCPs a Class of Service TLV may not ask for: "all", "none", or
 * a list of them, 0 to 63, by commas; false when it is not one. */
static bool
parse_dscps(const char *s, struct stamp_refl_conf *c)
{
	char		 buf[256], *p, *w;
	const char	*e;
	uint64_t	 m = 0;
	long long	 d;

	if (strcmp(s, "all") == 0) {
		c->dscp_deny = ~(uint64_t)0;
		return (true);
	}
	if (strcmp(s, "none") == 0) {
		c->dscp_deny = 0;
		return (true);
	}
	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return (false);
	for (p = buf; (w = strsep(&p, ",")) != NULL;) {
		d = strtonum(w, 0, 63, &e);
		if (e != NULL)
			return (false);
		m |= (uint64_t)1 << d;
	}
	c->dscp_deny = m;
	return (true);
}

/* The defaults. */
static void
conf_defaults(struct stamp_refl_conf *c)
{

	memset(c, 0, sizeof(*c));
	c->stateful = true;
	c->rate = 50;
	c->burst = 100;
	c->rate_total = 2000;
}

/*
 * The configuration file into c, over the defaults, the command line's
 * over it: "mode", "rate" and "rate-total", a word each and its value,
 * "#" a comment.  0, or -1 with why in why.
 */
static int
conf_read(struct stamp_refl_conf *c, char *why, size_t whylen)
{
	FILE	*fp;
	char	*line = NULL, *p, *key, *val;
	size_t	 cap = 0;
	int	 fd, n = 0, error = 0;

	conf_defaults(c);
	why[0] = '\0';
	if (conf_dir == -1)		/* no directory, and no -f */
		goto cmdline;
	if ((fd = openat(conf_dir, conf_name, O_RDONLY | O_CLOEXEC)) == -1) {
		if (errno == ENOENT && !conf_must)
			goto cmdline;
		(void)snprintf(why, whylen, "%s: %s", conf_name,
		    strerror(errno));
		return (-1);
	}
	if ((fp = fdopen(fd, "r")) == NULL) {
		(void)snprintf(why, whylen, "%s: %s", conf_name,
		    strerror(errno));
		close(fd);
		return (-1);
	}
	while (error == 0 && getline(&line, &cap, fp) != -1) {
		n++;
		if ((p = strchr(line, '#')) != NULL)
			*p = '\0';
		p = line;
		key = strsep(&p, " \t\n");
		while (p != NULL && (*p == ' ' || *p == '\t'))
			p++;
		val = p != NULL ? strsep(&p, " \t\n") : NULL;
		if (key == NULL || *key == '\0')
			continue;
		while (p != NULL && (*p == ' ' || *p == '\t' || *p == '\n'))
			p++;
		if (val == NULL || *val == '\0' || (p != NULL && *p != '\0') ||
		    !((strcmp(key, "mode") == 0 && parse_mode(val, c)) ||
		    (strcmp(key, "rate") == 0 && parse_rate(val, c)) ||
		    (strcmp(key, "rate-total") == 0 && parse_total(val, c)) ||
		    (strcmp(key, "dscp-refuse") == 0 && parse_dscps(val, c)) ||
		    (strcmp(key, "location") == 0 && parse_location(val, c)))) {
			(void)snprintf(why, whylen, "%s, line %d: \"%s\" is not "
			    "mode stateless|stateful, rate rate[/burst], "
			    "rate-total rate, dscp-refuse all|none|d,d,... or "
			    "location show|hide", conf_name, n, key);
			error = -1;
		}
	}
	free(line);
	fclose(fp);
	if (error != 0)
		return (-1);
cmdline:
	if (cl_set & SET_MODE)
		c->stateful = cl.stateful;
	if (cl_set & SET_RATE) {
		c->rate = cl.rate;
		c->burst = cl.burst;
	}
	if (cl_set & SET_TOTAL)
		c->rate_total = cl.rate_total;
	if (cl_set & SET_DSCP)
		c->dscp_deny = cl.dscp_deny;
	return (0);
}

static void
conf_say(const struct stamp_refl_conf *c, const char *what)
{
	char	rate[64], total[32];

	if (c->rate > 0)
		(void)snprintf(rate, sizeof(rate), "%g a second to a source, "
		    "bursts of %g", c->rate, c->burst > 0 ? c->burst :
		    c->rate * 2);
	else
		(void)snprintf(rate, sizeof(rate), "no limit to a source");
	if (c->rate_total > 0)
		(void)snprintf(total, sizeof(total), "%g a second in all",
		    c->rate_total);
	else
		(void)snprintf(total, sizeof(total), "no limit in all");
	syslog(LOG_INFO, "%s: %s, %s, %s, %d DSCPs refused a reply, "
	    "locations %s", what, c->stateful ? "stateful" : "stateless", rate,
	    total, __builtin_popcountll(c->dscp_deny), c->loc_hide ? "hidden" :
	    "shown");
}

/* The packets waiting on fd, each answered or dropped. */
static void
reflect(int fd)
{
	static uint8_t		 in[STAMP_PKT_MAX], out[STAMP_PKT_MAX];
	struct stamp_rxinfo	 ri;
	struct stamp_rx		 rx;
	struct timespec		 t3;
	char			 a[64];
	ssize_t			 n;
	int			 k;

	for (k = 0; k < BURST; k++) {
		if ((n = stamp_recv(fd, in, sizeof(in), &ri)) == -1)
			return;
		if (ri.trunc)
			continue;
		memset(&rx, 0, sizeof(rx));
		rx.pkt = in;
		rx.len = (size_t)n;
		rx.peer = (const struct sockaddr *)&ri.peer;
		rx.local = ri.local.ss_family != 0 ?
		    (const struct sockaddr *)&ri.local : NULL;
		rx.ttl = ri.ttl;
		rx.t2 = ri.t;
		rx.ts_in = ri.hwts ? STAMP_TSM_HW : STAMP_TSM_SW;
		rx.tos = ri.tos;
		rx.tag = fib;
		if ((n = stamp_refl_reply(refl, &rx, out, sizeof(out), NULL)) <
		    0)
			continue;
		clock_gettime(CLOCK_REALTIME, &t3);
		stamp_refl_send_time(out, &t3);
		if (stamp_send(fd, out, (size_t)n, rx.peer, rx.local,
		    ri.ifindex, stamp_refl_reply_tos(refl)) == -1)
			syslog(LOG_DEBUG, "a reply to %s: %m",
			    stamp_sa_ntop(rx.peer, a, sizeof(a)));
	}
}

/* The drops over the rate limits, said when they have grown. */
static void
drops_tell(void)
{
	struct stamp_refl_stats	st;

	stamp_refl_stats(refl, &st);
	if (st.dropped[STAMP_DROP_RATE] != drops_told)
		syslog(LOG_INFO, "%ju requests over the rate limits dropped",
		    (uintmax_t)st.dropped[STAMP_DROP_RATE]);
	drops_told = st.dropped[STAMP_DROP_RATE];
}

int
main(int argc, char *argv[])
{
	struct kevent	 kev[8];
	struct pidfh	*pfh = NULL;
	struct passwd	*pw = NULL;
	const char	*pidfile = NULL, *user = STAMPD_USER, *e;
	const char	*conf = PATH_STAMPD_CONF;
	char		 why[512], path[MAXPATHLEN];
	size_t		 len;
	pid_t		 other;
	int		 ch, kq, fds[2], nfds, i, n, port = STAMP_PORT, all;
	bool		 debug = false;

	while ((ch = getopt(argc, argv, "C:D:df:m:P:p:R:r:u:")) != -1)
		switch (ch) {
		case 'C':
			if (stamp_clock_set(optarg) == -1)
				errx(1, "-C %s: ntp, ptp, ssu, gnss or local, "
				    "and :error in seconds", optarg);
			break;
		case 'D':
			if (!parse_dscps(optarg, &cl))
				errx(1, "-D %s: all, none or DSCPs 0 to 63 by "
				    "commas", optarg);
			cl_set |= SET_DSCP;
			break;
		case 'd':
			debug = true;
			break;
		case 'f':
			conf = optarg;
			conf_must = true;
			break;
		case 'm':
			if (!parse_mode(optarg, &cl))
				errx(1, "-m %s: stateless or stateful", optarg);
			cl_set |= SET_MODE;
			break;
		case 'P':
			pidfile = optarg;
			break;
		case 'p':
			port = (int)strtonum(optarg, 1, 65535, &e);
			if (e != NULL)
				errx(1, "-p %s: %s", optarg, e);
			break;
		case 'R':
			if (!parse_total(optarg, &cl))
				errx(1, "-R %s: a rate, 0 to 10000000", optarg);
			cl_set |= SET_TOTAL;
			break;
		case 'r':
			if (!parse_rate(optarg, &cl))
				errx(1, "-r %s: rate[/burst], 0 to 1000000",
				    optarg);
			cl_set |= SET_RATE;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
		}
	if (argc != optind)
		usage();

	openlog("stampd", LOG_PID | LOG_NDELAY | (debug ? LOG_PERROR : 0),
	    LOG_DAEMON);
	if (!debug)
		setlogmask(LOG_UPTO(LOG_INFO));
	tzset();

	/* The file's directory kept, to read it again in the chroot. */
	if (strlcpy(path, conf, sizeof(path)) >= sizeof(path) ||
	    strlcpy(conf_name, basename(path), sizeof(conf_name)) >=
	    sizeof(conf_name))
		errx(1, "%s: too long", conf);
	(void)strlcpy(path, conf, sizeof(path));
	if ((conf_dir = open(dirname(path), O_DIRECTORY | O_CLOEXEC)) == -1 &&
	    conf_must)
		err(1, "%s", dirname(path));
	if (conf_read(&cur, why, sizeof(why)) == -1)
		errx(1, "%s", why);
	cur.port = (uint16_t)port;
	if ((refl = stamp_refl_new(&cur)) == NULL)
		err(1, "the reflector");

	if (geteuid() == 0 && (pw = getpwnam(user)) == NULL)
		errx(1, "no user %s: stampd gives up root to it (pw useradd "
		    "%s -d /var/empty -s /usr/sbin/nologin -c \"STAMP "
		    "reflector\")", user, user);
	len = sizeof(fib);
	if (sysctlbyname("net.my_fibnum", &fib, &len, NULL, 0) == -1)
		fib = 0;
	if (pidfile != NULL && (pfh = pidfile_open(pidfile, 0644, &other)) ==
	    NULL) {
		if (errno == EEXIST)
			errx(1, "already running in FIB %d, pid %jd", fib,
			    (intmax_t)other);
		err(1, "%s", pidfile);
	}

	/* A socket a family; a kernel or a jail without one, none. */
	nfds = 0;
	for (i = 0; i < 2; i++) {
		int	af = i == 0 ? AF_INET : AF_INET6, fd;

		if ((fd = stamp_socket(af, (uint16_t)port,
		    STAMP_SOCK_REFLECTOR)) == -1) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
			    errno == EADDRNOTAVAIL)
				continue;
			all = 0;
			len = sizeof(all);
			if (errno == EADDRINUSE && fib != 0 && sysctlbyname(
			    "net.inet.udp.bind_all_fibs", &all, &len, NULL,
			    0) == 0 && all != 0)
				syslog(LOG_ERR, "UDP %d in FIB %d: "
				    "net.inet.udp.bind_all_fibs is 1, FIB 0's "
				    "socket hears every FIB", port, fib);
			else
				syslog(LOG_ERR, "UDP %d in FIB %d (%s): %m", port,
				    fib, af == AF_INET ? "inet" : "inet6");
			pidfile_remove(pfh);
			exit(1);
		}
		fds[nfds++] = fd;
		syslog(LOG_INFO, "listening on UDP %d in FIB %d (%s)", port, fib,
		    af == AF_INET ? "inet" : "inet6");
	}
	if (nfds == 0) {
		syslog(LOG_ERR, "UDP %d in FIB %d: neither inet nor inet6",
		    port, fib);
		pidfile_remove(pfh);
		exit(1);
	}

	if (!debug && daemon(0, 0) == -1) {
		syslog(LOG_ERR, "daemon: %m");
		pidfile_remove(pfh);
		exit(1);
	}
	if (pfh != NULL)
		(void)pidfile_write(pfh);

	/* Bound: root given up. */
	if (pw != NULL) {
		if (chroot(PATH_EMPTY) == -1 || chdir("/") == -1) {
			syslog(LOG_ERR, "chroot %s: %m", PATH_EMPTY);
			exit(1);
		}
		if (setgroups(1, &pw->pw_gid) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
			syslog(LOG_ERR, "giving up root to %s: %m", user);
			exit(1);
		}
		syslog(LOG_DEBUG, "running as %s in %s", user, PATH_EMPTY);
	}
	conf_say(&cur, "started");

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR, "kqueue: %m");
		exit(1);
	}
	n = 0;
	for (i = 0; i < nfds; i++)
		EV_SET(&kev[n++], fds[i], EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[n++], SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[n++], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[n++], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[n++], 1, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, TICK_S, NULL);
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);
	if (kevent(kq, kev, n, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR, "kevent: %m");
		exit(1);
	}
	for (;;) {
		if ((n = kevent(kq, NULL, 0, kev, nitems(kev), NULL)) == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "kevent: %m");
			exit(1);
		}
		for (i = 0; i < n; i++) {
			struct stamp_refl_conf	 c;

			switch (kev[i].filter) {
			case EVFILT_READ:
				reflect((int)kev[i].ident);
				break;
			case EVFILT_TIMER:
				stamp_refl_expire(refl, 0);
				drops_tell();
				break;
			case EVFILT_SIGNAL:
				if (kev[i].ident != SIGHUP) {
					drops_tell();
					syslog(LOG_INFO, "stopping");
					pidfile_remove(pfh);
					exit(0);
				}
				if (conf_read(&c, why, sizeof(why)) == -1) {
					syslog(LOG_ERR, "%s: the configuration "
					    "kept as it was", why);
					break;
				}
				c.port = (uint16_t)port;
				if (stamp_refl_setconf(refl, &c) == -1) {
					syslog(LOG_ERR, "the configuration: %m");
					break;
				}
				cur = c;
				conf_say(&cur, "reloaded");
				break;
			}
		}
	}
}
