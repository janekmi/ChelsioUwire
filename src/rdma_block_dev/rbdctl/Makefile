CFLAGS = -Wall -g -D_GNU_SOURCE
OBJS = rbdctl.o
PROG = rbdctl
DEFS =

all: ${PROG}

${PROG}: ${OBJS}
rbdctl.o: rbdctl.c ../rbdi_dev.h

install: ${PROG}
	install -m 755 rbdctl $(PREFIX)/usr/bin
	gzip -c rbdctl.8 > rbdctl.8.gz
	@if [ -d $(PREFIX)/usr/share/man ];\
		then install -m 444 rbdctl.8.gz $(PREFIX)/usr/share/man/man8;\
	elif [ -d $(PREFIX)/usr/man ];\
		then install -m 444 rbdctl.8.gz $(PREFIX)/usr/man/man8;\
	fi
	@/bin/rm -f rbdctl.8.gz
 
clean:
	rm -f ${PROG} ${OBJS}
