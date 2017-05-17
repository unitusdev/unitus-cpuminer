
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

AM_CPPFLAGS	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS	= unitus_cpuminer

dist_man_MANS	= minerd.1

unitus_cpuminer_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  sha2.c \
		  sha3/sph_types.h sha3/aes_helper.c \
		  sha3/sph_blake.h sha3/sph_blake.c \
		  sha3/sph_bmw.h sha3/sph_bmw.c \
		  sha3/sph_cubehash.h sha3/sph_cubehash.c \
		  sha3/sph_echo.h sha3/sph_echo.c \
		  sha3/sph_groestl.h sha3/sph_groestl.c \
		  sha3/sph_jh.h sha3/sph_jh.c \
		  sha3/sph_keccak.h sha3/sph_keccak.c \
		  sha3/sph_luffa.h sha3/sph_luffa.c \
		  sha3/sph_shavite.h sha3/sph_shavite.c \
		  sha3/sph_simd.h sha3/sph_simd.c \
		  sha3/sph_skein.h sha3/sph_skein.c \
		  algo/lyra2rev2.c algo/Lyra2.h algo/Lyra2.c algo/Sponge.h algo/Sponge.c \
		  algo/skein.c \
		  algo/x11.c \
		  algo/sha256_Y.h algo/sha256_Y.c algo/sysendian.h algo/yescrypt.h algo/yescrypt.c \
		  algo/yescrypt-best.c algo/yescrypt-common.c algo/yescrypt-platform.h \
		  algo/argon2d.c algo/argon2/argon2.c algo/argon2/argon2.h algo/argon2/blake2.h algo/argon2/blake2b.c \
		  algo/argon2/blake2-impl.h algo/argon2/blamka-round-opt.h algo/argon2/core.c algo/argon2/core.h \
		  algo/argon2/encoding.c algo/argon2/enconding.h algo/argon2/opt.c algo/argon2/opt.h algo/argon2/thread.c algo/argon2/thread.h
if USE_ASM
if ARCH_x86
unitus_cpuminer_SOURCES += sha2-x86.S
endif
if ARCH_x86_64
unitus_cpuminer_SOURCES += sha2-x64.S
endif
if ARCH_ARM
unitus_cpuminer_SOURCES += sha2-arm.S
endif
if ARCH_PPC
unitus_cpuminer_SOURCES += sha2-ppc.S
endif
endif
unitus_cpuminer_LDFLAGS	= $(PTHREAD_FLAGS)
unitus_cpuminer_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
unitus_cpuminer_CPPFLAGS = @LIBCURL_CPPFLAGS@

