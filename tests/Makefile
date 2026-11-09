# The top of the installed test suite: ${TESTSBASE}/stamp/Kyuafile.

.include "${.CURDIR}/../share/mk/stamp.mk"

FILES=		Kyuafile
FILESDIR=	${TESTSBASE}/stamp

beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${FILESDIR}

.include <bsd.prog.mk>
