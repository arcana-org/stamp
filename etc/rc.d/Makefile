# stampd's rc(8) script, its program's path the PREFIX's.

.include "${.CURDIR}/../../share/mk/stamp.mk"

FILES=		stampd
FILESDIR=	${PREFIX}/etc/rc.d
FILESMODE=	0555
CLEANFILES=	stampd

stampd: stampd.in
	sed -e 's,%%PREFIX%%,${PREFIX},g' ${.ALLSRC} > ${.TARGET}

rc-dirs: .PHONY
	${INSTALL} -d ${DESTDIR}${FILESDIR}
beforeinstall: rc-dirs

.include <bsd.prog.mk>
