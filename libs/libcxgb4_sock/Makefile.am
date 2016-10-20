lib_LTLIBRARIES = src/libcxgb4_sock.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -D__USE_GNU -Dlint -I../libcxgb4_udp/include -DCONFIG_FILE=\"$(sysconfdir)/libcxgb4_sock.conf\"  -fno-strict-aliasing

src_libcxgb4_sock_la_SOURCES = src/sock.c src/route.c src/scanner.c src/parser.c src/endpoint.c
src_libcxgb4_sock_la_LDFLAGS = -version-info 1 -ldl -lc -pthread -lcxgb4_udp -libverbs -lrdmacm

EXTRA_DIST = src/libcxgb4_sock.h src/parser.h

dist-hook: libcxgb4_sock.spec
	cp libcxgb4_sock.spec $(distdir)

src/parser.c: src/parser.y
	$(YACC) -plibcxgb4_sock_yy -o src/parser.c -d src/parser.y

LEX = flex
src/scanner.c: src/scanner.l src/parser.c
	$(LEX) -Plibcxgb4_sock_yy -osrc/scanner.c src/scanner.l
