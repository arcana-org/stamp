.include "${.CURDIR}/../../../share/mk/stamp.mk"

TESTSDIR=	${TESTSBASE}/stamp/libstamp
ATF_TESTS_C=	libstamp_test

CFLAGS+=	${ST_CFLAGS}
LDADD+=		${.OBJDIR:H}/libstamp.a
DPADD+=		${.OBJDIR:H}/libstamp.a

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
