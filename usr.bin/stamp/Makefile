PROG=		stamp
MAN=		stamp.1

.include "${.CURDIR}/../../share/mk/stamp.mk"

CFLAGS+=	${ST_CFLAGS}
LDADD+=		${.OBJDIR}/../../lib/libstamp/libstamp.a -lm
DPADD+=		${.OBJDIR}/../../lib/libstamp/libstamp.a

stamp-dirs: .PHONY
	${INSTALL} -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}1
beforeinstall: stamp-dirs

.include <bsd.prog.mk>
