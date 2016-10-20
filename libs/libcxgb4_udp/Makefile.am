INCLUDES = -I$(srcdir)/include

lib_LTLIBRARIES = src/libcxgb4_udp.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DNDEBUG -fno-strict-aliasing

src_libcxgb4_udp_la_CFLAGS = $(AM_CFLAGS)

if HAVE_LD_VERSION_SCRIPT
    cxgb4_udp_version_script = -Wl,\
			       --version-script=$(srcdir)/src/libcxgb4_udp.map
else
    cxgb4_udp_version_script =
endif

src_libcxgb4_udp_la_SOURCES = src/udp.c
src_libcxgb4_udp_la_LDFLAGS = -version-info 1 -export-dynamic -pthread \
			      $(cxgb4_udp_version_script) -lrdmacm -lrt
src_libcxgb4_udp_la_DEPENDENCIES = $(srcdir)/src/libcxgb4_udp.map

bin_PROGRAMS = examples/udp_test
examples_udp_test_SOURCES = examples/udp_test.c examples/crc.c
examples_udp_test_LDADD = $(top_builddir)/src/libcxgb4_udp.la

libcxgb4_udpincludedir = $(includedir)/chelsio
libcxgb4_udpinclude_HEADERS = include/chelsio/cxgb4_udp.h \
			      include/chelsio/queue.h

EXTRA_DIST = include/chelsio/queue.h include/chelsio/cxgb4_udp.h \
	     src/cxgb4_udp.map libcxgb4_udp.spec.in

dist-hook: libcxgb4_udp.spec
	cp libcxgb4_udp.spec $(distdir)
