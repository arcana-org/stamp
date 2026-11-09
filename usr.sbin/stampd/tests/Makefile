.include "${.CURDIR}/../../../share/mk/stamp.mk"

TESTSDIR=	${TESTSBASE}/stamp/stampd
ATF_TESTS_SH=	stampd_test

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
