lib_LTLIBRARIES = src/libwdtoe.la

ACLOCAL_AMFLAGS = -I m4

src_libwdtoe_la_SOURCES = src/libwdtoe.c src/get_clock.c src/stats.c src/conn_info.c \
			  src/kernelcom.c src/mmap.c src/chardev.c src/buffer.c \
			  src/cpl.c
src_libwdtoe_la_LDFLAGS = -version-info 1 -lc -lm -ldl -lpthread

EXTRA_DIST = examples/wdtoe.conf

install-config-file:
	cp examples/wdtoe.conf $(sysconfdir)/wdtoe.conf

uninstall-config-file:
	rm -f $(sysconfdir)/wdtoe.conf

install-exec-local: install-config-file
uninstall-local: uninstall-config-file
