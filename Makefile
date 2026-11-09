# stamp, built with base make(1) and bsd.*.mk:
#
#	make && make check
#	make install [DESTDIR=dir] [PREFIX=/usr/local]
#	kyua test -k ${PREFIX}/tests/stamp/Kyuafile
#
# Build products go to obj/, mirroring the tree (share/mk/stamp.mk),
# unless MAKEOBJDIRPREFIX says where else.  WITHOUT_TESTS=yes builds and
# installs no tests.  "make check" runs the tests in the build tree with
# kyua(1); those that need root are skipped without it.

.include "share/mk/stamp.mk"

SUBDIR=		lib/libstamp \
		usr.sbin/stampd \
		usr.bin/stamp \
		etc/rc.d
SUBDIR.${MK_TESTS}+= tests
SUBDIR_DEPEND_usr.sbin/stampd=	lib/libstamp
SUBDIR_DEPEND_usr.bin/stamp=	lib/libstamp

TESTDIRS=	lib/libstamp/tests \
		usr.sbin/stampd/tests

# "all" as a dependency would not recurse: bsd.subdir.mk only descends
# for targets named on the command line.
check: .PHONY
	@${MAKE} -C ${.CURDIR} all
	@{ echo 'syntax(2)'; echo 'test_suite("stamp")'; \
	    for d in ${TESTDIRS}; do echo "include(\"$$d/Kyuafile\")"; \
	    done; } > ${.OBJDIR}/Kyuafile
	@cd ${.OBJDIR} && kyua test -k Kyuafile || \
	    { kyua report --verbose --results-filter broken,failed; exit 1; }

# Everything built is under obj/.
clean cleandir: .PHONY
	rm -rf ${ST_TOP}/obj

.include <bsd.subdir.mk>
