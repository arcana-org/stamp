#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# stampd(8) answering stamp(1), on a high port of the loopback, as any
# user; the cases that need root say so.

# The programs: the build tree's, else the installed ones.
programs()
{
	local s=$(atf_get_srcdir)

	D=$s/../stampd
	[ -x "$D" ] || D=$(atf_config_get stampd /usr/local/sbin/stampd)
	S=$s/../../../usr.bin/stamp/stamp
	[ -x "$S" ] || S=$(atf_config_get stamp /usr/local/bin/stamp)
	RC=$s/../../../etc/rc.d/stampd
	[ -f "$RC" ] || RC=$(atf_config_get stampd_rc /usr/local/etc/rc.d/stampd)
	# Run by root, it gives up root: to nobody, here.
	U=
	[ "$(id -u)" = 0 ] && U="-u nobody"
	true
}

# A port of its own.
port()
{
	jot -r 1 20000 59999
}

# stampd in the foreground with "$@", its log in d.out, until it says
# it listens.
start()
{
	local i

	programs
	: > d.out
	"$D" -d $U -P "$(pwd)/stampd.pid" "$@" > d.out 2>&1 &
	echo $! > d.pid
	for i in $(seq 1 100); do
		grep -q 'started' d.out && return 0
		sleep 0.05
	done
	atf_fail "stampd did not start: $(cat d.out)"
}

stop()
{
	[ -f d.pid ] && kill "$(cat d.pid)" 2>/dev/null
	rm -f d.pid
	true
}

has_inet6()
{
	ifconfig lo0 inet6 2>/dev/null | grep -q '::1'
}

# Wait until what "$@" prints matches $1 (grep -E): 10 s at most.
wait_match()
{
	local re=$1 i

	shift
	for i in $(seq 1 100); do
		"$@" 2>/dev/null | grep -Eq -e "$re" && return 0
		sleep 0.1
	done
	return 1
}

LINE='echo=ok order=ok clock=ok serr=ok mbz=ok pad=ok rtt='

atf_test_case stateless cleanup
stateless_head()
{
	atf_set "descr" "Stateless: the sender's sequence number copied, its" \
	    "timestamp, error estimate and SSID echoed, T2 before T3, the" \
	    "TTL it came with; IPv4 and IPv6; a reply exactly as long as its" \
	    "request; under 44 octets (a bare TWAMP Light packet) none"
}
stateless_body()
{
	P=$(port)
	start -m stateless -p $P
	atf_check -o match:"^len=44 from=127\.0\.0\.1 seq=7 ssid=4660 sseq=7 ttl=77 rttl=255 $LINE" \
	    "$S" -p $P -q 7 -s 4660 -t 77 127.0.0.1
	# The sender's number again: copied, never counted.
	atf_check -o match:'^len=44 from=127\.0\.0\.1 seq=7 ssid=4660 sseq=7 ' \
	    "$S" -p $P -q 7 -s 4660 127.0.0.1
	atf_check -o save:three.out "$S" -p $P -q 100 -s 1 -c 3 -i 0 127.0.0.1
	atf_check -o match:'^len=44 .* seq=100 ssid=1 sseq=100 ' \
	    -o match:'^len=44 .* seq=101 ssid=1 sseq=101 ' \
	    -o match:'^len=44 .* seq=102 ssid=1 sseq=102 ' \
	    -o match:'^sent=3 received=3 rtt=' cat three.out
	if has_inet6; then
		atf_check -o match:"^len=44 from=::1 seq=3 ssid=5 sseq=3 ttl=33 rttl=255 $LINE" \
		    "$S" -p $P -q 3 -s 5 -t 33 ::1
	fi
	# Longer: exactly as long back, what follows the base copied.
	atf_check -o match:'^len=200 .* seq=6 .* pad=ok ' \
	    "$S" -p $P -q 6 -l 200 127.0.0.1
	atf_check -o match:'^len=45 .* seq=9 .* pad=ok ' \
	    "$S" -p $P -q 9 -l 45 127.0.0.1
	# Shorter than the reply would be: none, never an amplifier.
	for n in 14 43 13 0; do
		atf_check -s exit:2 -o inline:'none\n' \
		    "$S" -p $P -l $n -W 0.5 127.0.0.1
	done
	atf_check -o match:'^len=44 .* seq=8 ' "$S" -p $P -q 8 127.0.0.1
}
stateless_cleanup()
{
	stop
}

atf_test_case stateful cleanup
stateful_head()
{
	atf_set "descr" "Stateful (RFC 8762 4.3.2): a counter a session, a" \
	    "session the sender's address, port and SSID (RFC 8972)," \
	    "whatever the sender's numbers"
}
stateful_body()
{
	P=$(port)
	SP=$(port)
	start -p $P
	atf_check -o save:a.out "$S" -p $P -S $SP -s 1 -q 500 -c 3 -i 0 127.0.0.1
	atf_check -o match:'^len=44 .* seq=0 ssid=1 sseq=500 ' \
	    -o match:'^len=44 .* seq=1 ssid=1 sseq=501 ' \
	    -o match:'^len=44 .* seq=2 ssid=1 sseq=502 ' cat a.out
	# Another SSID from the same port: a session of its own.
	atf_check -o match:'^len=44 .* seq=0 ssid=2 sseq=9 ' \
	    "$S" -p $P -S $SP -s 2 -q 9 127.0.0.1
	# A request under 44 octets counts nothing; the first goes on.
	atf_check -s exit:2 -o inline:'none\n' \
	    "$S" -p $P -S $SP -s 1 -q 503 -l 43 -W 0.5 127.0.0.1
	atf_check -o match:'^len=200 .* seq=3 ssid=1 sseq=504 .* pad=ok ' \
	    "$S" -p $P -S $SP -s 1 -q 504 -l 200 127.0.0.1
	# The same SSID from another port: another session.
	atf_check -o match:'^len=44 .* seq=0 ssid=1 sseq=1 ' \
	    "$S" -p $P -s 1 -q 1 127.0.0.1
	if has_inet6; then
		atf_check -o save:b.out "$S" -p $P -S $SP -s 1 -c 2 -i 0 ::1
		atf_check -o match:'^len=44 from=::1 seq=0 ssid=1 sseq=0 ' \
		    -o match:'^len=44 from=::1 seq=1 ssid=1 sseq=1 ' cat b.out
	fi
}
stateful_cleanup()
{
	stop
}

atf_test_case rate cleanup
rate_head()
{
	atf_set "descr" "The rate limits: a burst over a source's bucket" \
	    "mostly dropped, the drops logged; another source answered" \
	    "meanwhile; the cap of all of them; wrong values refused"
	atf_set "timeout" "60"
}
rate_body()
{
	P=$(port)
	start -m stateless -p $P -r 2/4
	"$S" -p $P -c 30 -i 0 -W 0.05 127.0.0.1 > burst.out
	n=$(grep -c '^len=44' burst.out)
	d=$(grep -c '^none$' burst.out)
	[ "$n" -ge 4 -a "$n" -le 12 ] ||
	    atf_fail "$n of 30 answered over 2/s, bursts of 4"
	[ "$d" -ge 18 ] || atf_fail "only $d of 30 dropped"
	if has_inet6; then
		atf_check -o match:'^len=44 ' "$S" -p $P ::1
	fi
	wait_match '[0-9]+ requests over the rate limits dropped' cat d.out ||
	    atf_fail "no drops told: $(cat d.out)"
	sleep 2
	atf_check -o match:'^len=44 .* seq=5 ' "$S" -p $P -q 5 127.0.0.1
	stop
	start -m stateless -p $P -R 3
	"$S" -p $P -c 20 -i 0 -W 0.05 127.0.0.1 > all.out
	n=$(grep -c '^len=44' all.out)
	[ "$n" -ge 3 -a "$n" -le 8 ] ||
	    atf_fail "$n of 20 answered under a cap of 3/s"
	stop
	atf_check -s exit:1 -e match:'-r 5/x' "$D" -d -r 5/x
	atf_check -s exit:1 -e match:'-r x' "$D" -d -r x
	atf_check -s exit:1 -e match:'-R -1' "$D" -d -R -1
	atf_check -s exit:1 -e match:'-m x: stateless or stateful' "$D" -d -m x
	atf_check -s exit:1 -e match:'usage' "$D" -d extra
}
rate_cleanup()
{
	stop
}

atf_test_case reload cleanup
reload_head()
{
	atf_set "descr" "The configuration file, read again on SIGHUP: its" \
	    "mode and rates; the command line's kept over it; a wrong one" \
	    "logged, the configuration kept"
}
reload_body()
{
	P=$(port)
	SP=$(port)
	printf '# stampd\nmode stateless\nrate 100/200 # a source\n' > conf
	start -p $P -f "$(pwd)/conf"
	atf_check -o match:'started: stateless, 100 a second to a source, bursts of 200, 2000 a second in all' \
	    cat d.out
	atf_check -o match:'^len=44 .* seq=40 ' "$S" -p $P -S $SP -q 40 127.0.0.1
	printf 'mode stateful\nrate-total 500\n' > conf
	kill -HUP "$(cat d.pid)"
	wait_match 'reloaded: stateful, 50 a second to a source, bursts of 100, 500 a second in all' \
	    cat d.out || atf_fail "not reloaded: $(cat d.out)"
	atf_check -o match:'^len=44 .* seq=0 .* sseq=41 ' \
	    "$S" -p $P -S $SP -q 41 127.0.0.1
	# Wrong: logged, the configuration as it was, the session too.
	printf 'mode stateful\nrate fast\n' > conf
	kill -HUP "$(cat d.pid)"
	wait_match 'conf, line 2: "rate" is not' cat d.out ||
	    atf_fail "not refused: $(cat d.out)"
	atf_check -o match:'^len=44 .* seq=1 .* sseq=42 ' \
	    "$S" -p $P -S $SP -q 42 127.0.0.1
	stop
	# The command line over the file, on a reload too.
	printf 'mode stateful\n' > conf
	start -p $P -f "$(pwd)/conf" -m stateless
	kill -HUP "$(cat d.pid)"
	wait_match 'reloaded: stateless' cat d.out ||
	    atf_fail "-m not kept: $(cat d.out)"
	stop
	# -f: there, or no start.
	atf_check -s exit:1 -e match:'nothere' "$D" -d -p $P -f "$(pwd)/nothere"
}
reload_cleanup()
{
	stop
}

# FIB 1 can reach 127.0.0.1 (net.add_addr_allfibs, or a route there).
fib1()
{
	[ "$(sysctl -n net.fibs)" -ge 2 ] || atf_skip "net.fibs is 1"
	[ "$(sysctl -n net.inet.udp.bind_all_fibs)" = 0 ] ||
	    atf_skip "net.inet.udp.bind_all_fibs is 1: one socket for all"
	netstat -rn -F 1 -f inet 2>/dev/null | grep -q '^127\.0\.0\.1 ' ||
	    atf_skip "FIB 1 has no route to 127.0.0.1"
}

atf_test_case fib cleanup
fib_head()
{
	atf_set "descr" "One stampd a FIB: started in FIB 1 by setfib(1), it" \
	    "answers FIB 1's packets alone, and another binds the same port" \
	    "in FIB 0, its sessions apart"
}
fib_body()
{
	fib1
	P=$(port)
	SP=$(port)
	programs
	: > d.out
	setfib 1 "$D" -d $U -p $P > d.out 2>&1 &
	echo $! > d.pid
	wait_match 'started' cat d.out || atf_fail "$(cat d.out)"
	atf_check -o match:"listening on UDP $P in FIB 1 \(inet\)" cat d.out
	atf_check -o match:'^len=44 .* seq=0 .* sseq=5 ' \
	    setfib 1 "$S" -p $P -S $SP -q 5 127.0.0.1
	atf_check -s exit:2 -o inline:'none\n' \
	    "$S" -p $P -S $SP -W 0.5 127.0.0.1
	"$D" -d $U -p $P > d0.out 2>&1 &
	echo $! > d0.pid
	wait_match 'started' cat d0.out || atf_fail "$(cat d0.out)"
	atf_check -o match:'^len=44 .* seq=0 .* sseq=6 ' \
	    "$S" -p $P -S $SP -q 6 127.0.0.1
	atf_check -o match:'^len=44 .* seq=1 .* sseq=7 ' \
	    setfib 1 "$S" -p $P -S $SP -q 7 127.0.0.1
}
fib_cleanup()
{
	stop
	[ -f d0.pid ] && kill "$(cat d0.pid)" 2>/dev/null
	true
}

# The rc script as ./rc verb: its variables from the environment, which
# the host's rc.conf does not set, stampd_fibs ./fibs' words.  As root:
# rc.subr runs the program under limits(1)'s daemon class, which a user
# may not raise its limits to.
rc_write()
{
	cat > rc <<EOF
#!/bin/sh
exec env stampd_enable=YES stampd_fibs="\$(cat fibs)" stampd_program="$D" \\
    stampd_flags="-p $P -u nobody" stampd_rundir="$(pwd)/run" /bin/sh "$RC" "\$@"
EOF
	chmod +x rc
}

atf_test_case rc_script cleanup
rc_script_head()
{
	atf_set "descr" "The rc script: a stampd for each FIB of stampd_fibs" \
	    "(rc.subr's stampd_fib), its pidfile run/fib<N>.pid; reload" \
	    "stops those no longer listed, starts the new and tells the" \
	    "others to read their file again, their sessions kept"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
rc_script_body()
{
	fib1
	programs
	P=$(port)
	SP=$(port)
	rc_write
	echo 0 > fibs
	atf_check -o ignore -e ignore ./rc start
	atf_check test -f run/fib0.pid
	pid0=$(cat run/fib0.pid)
	atf_check -o match:'^len=44 .* seq=0 .* sseq=1 ' \
	    "$S" -p $P -S $SP -q 1 127.0.0.1
	atf_check -s exit:2 -o inline:'none\n' \
	    setfib 1 "$S" -p $P -W 0.5 127.0.0.1
	# FIB 1 added: started; FIB 0's told, its session going on.
	echo "0 1" > fibs
	atf_check -o ignore -e ignore ./rc reload
	atf_check test -f run/fib1.pid
	atf_check_equal "$pid0" "$(cat run/fib0.pid)"
	wait_match '^len=44 .* seq=0 ' setfib 1 "$S" -p $P -W 0.2 127.0.0.1 ||
	    atf_fail "FIB 1 not answered"
	atf_check -o match:'^len=44 .* seq=1 .* sseq=2 ' \
	    "$S" -p $P -S $SP -q 2 127.0.0.1
	atf_check -o match:'is running as pid' ./rc status
	# Unknown words and FIBs past net.fibs passed over, said.
	echo "0,1 x 999" > fibs
	atf_check -o ignore -e match:'"x" is not a FIB' \
	    -e match:'FIB 999: net.fibs is' ./rc reload
	# FIB 0 dropped: stopped, FIB 1's kept.
	echo 1 > fibs
	pid1=$(cat run/fib1.pid)
	atf_check -o ignore -e ignore ./rc reload
	atf_check_equal "$pid1" "$(cat run/fib1.pid)"
	wait_match '^none$' "$S" -p $P -W 0.2 127.0.0.1 ||
	    atf_fail "FIB 0 still answered"
	echo "0 1" > fibs
	atf_check -s exit:1 -o match:'not running in FIB 0' \
	    -o match:'is running as pid' ./rc status
	echo 1 > fibs
	atf_check -o ignore -e ignore ./rc stop
	wait_match '^none$' setfib 1 "$S" -p $P -W 0.2 127.0.0.1 ||
	    atf_fail "FIB 1 still answered"
	atf_check -s exit:1 -o match:'not running in FIB 1' ./rc status
}
rc_script_cleanup()
{
	local pf

	for pf in run/fib*.pid; do
		[ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null
	done
	true
}

atf_test_case privileges cleanup
privileges_head()
{
	atf_set "descr" "Run by root: bound, it gives up root to its user and" \
	    "its root directory to /var/empty, and answers still; no such" \
	    "user, no start"
	atf_set "require.user" "root"
}
privileges_body()
{
	P=$(port)
	start -p $P -u nobody
	pid=$(cat d.pid)
	atf_check -o inline:'nobody\n' ps -o user= -p $pid
	atf_check -o match:'running as nobody in /var/empty' cat d.out
	atf_check -o match:' root .* /var/empty' procstat -f $pid
	atf_check -o match:'^len=44 ' "$S" -p $P 127.0.0.1
	kill -HUP $pid
	wait_match 'reloaded' cat d.out || atf_fail "$(cat d.out)"
	atf_check -s exit:1 -e match:'no user no_such_stampd_user' \
	    "$D" -d -p $P -u no_such_stampd_user
}
privileges_cleanup()
{
	stop
}

atf_init_test_cases()
{
	atf_add_test_case stateless
	atf_add_test_case stateful
	atf_add_test_case rate
	atf_add_test_case reload
	atf_add_test_case fib
	atf_add_test_case rc_script
	atf_add_test_case privileges
}
