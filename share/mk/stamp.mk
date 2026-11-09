# Common settings, included by every Makefile in the tree:
#
#	.include "${.CURDIR}/<path to top>/share/mk/stamp.mk"

.if !target(__<stamp.mk>__)
__<stamp.mk>__:

ST_TOP:=	${.PARSEDIR:tA:H:H}

# Build products go to ${ST_TOP}/obj, mirroring the tree, unless
# MAKEOBJDIRPREFIX or MAKEOBJDIR in the environment says where else (a
# tree that has this one as a submodule may say so).
.if !defined(MAKEOBJDIRPREFIX) && !defined(MAKEOBJDIR)
.if ${.CURDIR:tA} == ${ST_TOP}
ST_OBJDIR=	${ST_TOP}/obj
.else
ST_OBJDIR=	${ST_TOP}/obj/${.CURDIR:tA:S,^${ST_TOP}/,,}
.endif
.if ${.OBJDIR:tA} != ${ST_OBJDIR}
__objdir!=	mkdir -p ${ST_OBJDIR} && echo ${ST_OBJDIR}
.OBJDIR:	${ST_OBJDIR}
.endif
.endif

.include <bsd.opts.mk>

PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/bin
LIBDIR?=	${PREFIX}/lib
INCLUDEDIR?=	${PREFIX}/include
MANDIR?=	${PREFIX}/share/man/man
TESTSBASE?=	${PREFIX}/tests

CSTD?=		c17
WARNS?=		6

# libstamp, built here, for the programs and the tests: its objects
# mirror the tree, so a directory's way to it is its way in the sources.
ST_CFLAGS=	-I${ST_TOP}/lib/libstamp

# atf.test.mk only knows LDADD_atf_c inside the source tree; base ships
# atf-c as a private library with its header in /usr/include.
LDADD_atf_c=	-lprivateatf-c

.endif
