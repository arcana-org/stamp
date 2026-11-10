# libstamp: STAMP's packets, timestamps, Session-Reflector and
# Session-Sender, for stampd(8), stamp(1) and another tree's programs
# (arcana-agent's sender).  A
# static library, its objects position-independent so that a PIE or a
# shared object links it; installed with its header for that.

LIB=		stamp
SRCS=		stamp_ts.c stamp_pkt.c stamp_auth.c stamp_refl.c stamp_send.c \
		stamp_net.c
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
