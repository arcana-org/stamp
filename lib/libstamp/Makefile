# libstamp: STAMP's packets, timestamps and Session-Reflector, for
# stampd(8), stamp(1) and a program of another tree's (a sender).  A
# static library, its objects position-independent so that a PIE or a
# shared object links it; installed with its header for that.

LIB=		stamp
SRCS=		stamp_ts.c stamp_pkt.c stamp_refl.c stamp_net.c
INCS=		stamp.h
MAN=		libstamp.3

.include "${.CURDIR}/../../share/mk/stamp.mk"

CFLAGS+=	-fPIC

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

libstamp-dirs: .PHONY
	${INSTALL} -d ${DESTDIR}${LIBDIR} ${DESTDIR}${INCLUDEDIR} \
	    ${DESTDIR}${MANDIR}3
beforeinstall: libstamp-dirs

.include <bsd.lib.mk>

# The tests link the library: under make -j, build it first.
all_subdir_${DIRPRFX}tests: ${_LIBS}
