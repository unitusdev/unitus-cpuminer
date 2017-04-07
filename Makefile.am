
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

AM_CPPFLAGS	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  sha2.c scrypt.c \
		  sha3/sph_types.h \
		  sha3/sph_skein.h sha3/sph_skein.c \
		  sha3/sph_blake.h sha3/sph_blake.c \
		  sha3/sph_bmw.h sha3/sph_bmw.c \
		  sha3/sph_cubehash.h sha3/sph_cubehash.c \
		  sha3/sph_keccak.h sha3/sph_keccak.c \
		  algo/lyra2rev2.c algo/Lyra2.h algo/Lyra2.c algo/Sponge.h algo/Sponge.c \
		  algo/skein.c 
if USE_ASM
if ARCH_x86
minerd_SOURCES += sha2-x86.S scrypt-x86.S
endif
if ARCH_x86_64
minerd_SOURCES += sha2-x64.S scrypt-x64.S
endif
if ARCH_ARM
minerd_SOURCES += sha2-arm.S scrypt-arm.S
endif
if ARCH_PPC
minerd_SOURCES += sha2-ppc.S scrypt-ppc.S
endif
endif
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@

