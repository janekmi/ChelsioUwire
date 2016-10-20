DEFS = -DUSE_STD_VECTOR
DEBUG = -g
ARCH = 
CXXFLAGS = -O2 -Wall -Werror $(DEBUG) $(DEFS) $(ARCH)
CFLAGS = -O2 -Wall -Werror $(DEBUG) $(ARCH)
LDFLAGS = $(ARCH)

PROGS = cop opt
COP_OBJS = cop.o classifier.o ipfilter.o
OPT_OBJS = opt.o
OBJS = $(COP_OBJS) $(OPT_OBJS)

all: $(PROGS)

cop: $(COP_OBJS)
	$(CXX) $(LDFLAGS) $(DEBUG) -o cop $(COP_OBJS)

opt: $(OPT_OBJS)
	$(CC) $(LDFLAGS) $(DEBUG) -o opt $(OPT_OBJS)

VECTOR_DEPS = vector.cc vector.h

$(OBJS): Makefile
classifier.o: classifier.h error.h offload_req.h $(VECTOR_DEPS)
cop.o: classifier.h error.h ipfilter.h offload_req.h $(VECTOR_DEPS)
ipfilter.o: classifier.h error.h ipfilter.h offload_req.h $(VECTOR_DEPS)
opt.o: offload_req.h

install: cop
	install -m 755 cop $(PREFIX)/sbin
	gzip -c cop.8 > cop.8.gz
	@if [ -d $(PREFIX)/usr/share/man ];\
		then install -m 444 cop.8.gz $(PREFIX)/usr/share/man/man8;\
	elif [ -d $(PREFIX)/usr/man ];\
		then install -m 444 cop.8.gz $(PREFIX)/usr/man/man8;\
	fi
	@/bin/rm -f cop.8.gz

clean:
	/bin/rm -f ${PROGS} ${OBJS}
