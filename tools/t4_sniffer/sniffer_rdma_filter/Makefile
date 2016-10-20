TESTS = sniffer

all: ${TESTS}

CFLAGS += -Wall -g -D_GNU_SOURCE -O2
EXTRA_FILES = get_clock.c
EXTRA_HEADERS = get_clock.h
LOADLIBES += 
LDFLAGS += 

${TESTS}: LOADLIBES += -libverbs -lrdmacm -lpthread -lrt

${TESTS} ${UTILS}: %: %.c ${EXTRA_FILES} ${EXTRA_HEADERS}
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< ${EXTRA_FILES} $(LOADLIBES) $(LDLIBS) -o $@
clean:
	rm -f ${TESTS} ${UTILS}
.DELETE_ON_ERROR:
.PHONY: all clean
