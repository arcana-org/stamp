PROG=		stampd
MAN=		stampd.8

.include "${.CURDIR}/../../share/mk/stamp.mk"

BINDIR=		${PREFIX}/sbin
CFLAGS+=	${ST_CFLAGS} -DPATH_STAMPD_CONF=\"${PREFIX}/etc/stampd.conf\"
LDADD+=		${.OBJDIR}/../../lib/libstamp/libstamp.a -lutil
DPADD+=		${.OBJDIR}/../../lib/libstamp/libstamp.a

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

stampd-dirs: .PHONY
	${INSTALL} -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}8
beforeinstall: stampd-dirs

.include <bsd.prog.mk>
